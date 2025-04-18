import { useMemo, useState } from "react";
import { ResultsDisplay, TokenField, TransactionButton, UserDataInput } from ".";
import { PERMIT2, SwapInput, SwapKind, VAULT_V3, vaultV3Abi } from "@balancer/sdk";
import { useQueryClient } from "@tanstack/react-query";
import { parseUnits } from "viem";
import { useContractEvent } from "wagmi";
import { Alert } from "~~/components/common";
import { useQuerySwap, useSwap, useTargetFork } from "~~/hooks/balancer/";
import { PoolActionsProps, PoolOperationReceipt, SwapConfig } from "~~/hooks/balancer/types";
import { useAllowanceOnToken, useApproveOnToken } from "~~/hooks/token";
import { formatToHex } from "~~/utils/helpers";

const initialSwapConfig: SwapConfig = {
  tokenIn: {
    poolTokensIndex: 0,
    amount: "",
    rawAmount: 0n,
  },
  tokenOut: {
    poolTokensIndex: 1,
    amount: "",
    rawAmount: 0n,
  },
  swapKind: SwapKind.GivenOut,
  userData: "0x",
};

/**
 * 1. Choose tokenIn and tokenOut
 * 2. Query swapping some amount of tokens in the pool
 * 3. Approve the vault for the tokenIn used in the swap transaction (if necessary)
 * 4. Send transaction to swap the tokens
 */
export const SwapForm: React.FC<PoolActionsProps> = ({ pool, refetchPool, tokenBalances, refetchTokenBalances }) => {
  const [swapConfig, setSwapConfig] = useState<SwapConfig>(initialSwapConfig);
  const [swapReceipt, setSwapReceipt] = useState<PoolOperationReceipt>(null);
  const [userDataInputValue, setUserDataInputValue] = useState<string>("0x");

  const { chainId } = useTargetFork();
  const queryClient = useQueryClient();

  // Make sure pool.poolTokens is an array and has the necessary elements
  const tokenIn = pool.poolTokens?.[swapConfig.tokenIn.poolTokensIndex];
  const tokenOut = pool.poolTokens?.[swapConfig.tokenOut.poolTokensIndex];

  // Only create swapInput if both tokenIn and tokenOut are available
  const swapInput: SwapInput | null =
    tokenIn && tokenOut
      ? {
          chainId,
          swapKind: swapConfig.swapKind,
          paths: [
            {
              pools: [pool.address as `0x${string}`],
              tokens: [
                { address: tokenIn.address as `0x${string}`, decimals: tokenIn.decimals }, // tokenIn
                { address: tokenOut.address as `0x${string}`, decimals: tokenOut.decimals }, // tokenOut
              ],
              protocolVersion: 3 as const,
              inputAmountRaw: swapConfig.tokenIn.rawAmount,
              outputAmountRaw: swapConfig.tokenOut.rawAmount,
            },
          ],
          userData: swapConfig.userData,
        }
      : null;

  const {
    data: queryResponse,
    isFetching: isQueryFetching,
    error: queryError,
    refetch: refetchQuerySwap,
  } = useQuerySwap(swapInput, setSwapConfig);

  const { data: allowanceOnToken, refetch: refetchAllowanceOnToken } = useAllowanceOnToken(
    tokenIn?.address,
    PERMIT2[chainId],
  );

  const {
    mutateAsync: approveOnToken,
    isPending: isApprovePending,
    error: approveError,
  } = useApproveOnToken(tokenIn?.address, PERMIT2[chainId]);

  const { mutate: swap, isPending: isSwapPending, error: swapError } = useSwap(swapInput);

  const handleQuerySwap = async () => {
    queryClient.removeQueries({ queryKey: ["querySwap"] });
    setSwapReceipt(null);
    refetchQuerySwap();
  };

  const handleApprove = async () => {
    await approveOnToken();
    refetchAllowanceOnToken();
  };

  const handleSwap = async () => {
    try {
      swap(queryResponse, {
        onSuccess: () => {
          refetchPool();
          refetchTokenBalances();
        },
        onError: error => {
          // Special case for invariant ratio errors
          if (
            typeof error === "object" &&
            error &&
            "message" in error &&
            typeof error.message === "string" &&
            (error.message.includes("0x340a4533") || error.message.includes("invariant"))
          ) {
            console.error("Invariant ratio error detected. Trying with a smaller amount might help.");
          }

          // We let the error handler in the component display the error
          console.error("Swap error:", error);
        },
      });
    } catch (error) {
      console.error("Error during swap:", error);
    }
  };

  const handleTokenAmountChange = (amount: string, swapConfigKey: "tokenIn" | "tokenOut") => {
    // Clear previous results when the amount changes
    queryClient.removeQueries({ queryKey: ["querySwap"] });
    setSwapReceipt(null);

    // Ensure tokens are available before calculating rawAmount
    if (!tokenIn || !tokenOut) return;

    // Update the focused input amount with new value and reset the other input amount
    setSwapConfig(prevConfig => ({
      ...prevConfig,
      tokenIn: {
        ...prevConfig.tokenIn,
        amount: swapConfigKey === "tokenIn" ? amount : "",
        rawAmount: swapConfigKey === "tokenIn" && amount ? parseUnits(amount || "0", tokenIn.decimals) : 0n,
      },
      tokenOut: {
        ...prevConfig.tokenOut,
        amount: swapConfigKey === "tokenOut" ? amount : "",
        rawAmount: swapConfigKey === "tokenOut" && amount ? parseUnits(amount || "0", tokenOut.decimals) : 0n,
      },
      swapKind: swapConfigKey === "tokenIn" ? SwapKind.GivenIn : SwapKind.GivenOut,
    }));
  };

  const handleUserDataChange = (userData: string) => {
    queryClient.removeQueries({ queryKey: ["querySwap"] });
    setSwapReceipt(null);
    setUserDataInputValue(userData);

    setSwapConfig(prevConfig => ({
      ...prevConfig,
      userData: formatToHex(userData),
    }));
  };

  // Only register the event if tokens are defined
  useContractEvent({
    address: VAULT_V3[chainId],
    abi: vaultV3Abi,
    eventName: "Swap",
    listener(log: any[]) {
      // Only process the event if tokens are defined
      if (!tokenIn || !tokenOut) return;

      const data = [
        {
          decimals: tokenOut.decimals,
          rawAmount: log[0].args.amountOut,
          symbol: tokenOut.symbol,
          name: tokenOut.name,
        },
        {
          decimals: tokenIn.decimals,
          rawAmount: log[0].args.amountIn,
          symbol: tokenIn.symbol,
          name: tokenIn.name,
        },
      ];

      setSwapReceipt({ data, transactionHash: log[0].transactionHash });
    },
  });

  const sufficientAllowance = useMemo(() => {
    return allowanceOnToken && allowanceOnToken >= swapConfig.tokenIn.rawAmount;
  }, [allowanceOnToken, swapConfig.tokenIn.rawAmount]);

  const isFormEmpty = swapConfig.tokenIn.amount === "" && swapConfig.tokenOut.amount === "";
  const error: Error | null = queryError || swapError || approveError;

  // Early return if tokens are not available
  if (!tokenIn || !tokenOut) {
    return (
      <section className="flex flex-col gap-5">
        <Alert type="warning">Pool tokens not available. Please select a valid pool.</Alert>
      </section>
    );
  }

  return (
    <section className="flex flex-col gap-5">
      <TokenField
        label="Token In"
        token={tokenIn}
        pool={pool}
        userBalance={tokenBalances[tokenIn.address]}
        value={swapConfig.tokenIn.amount}
        onAmountChange={value => handleTokenAmountChange(value, "tokenIn")}
        setSwapConfig={setSwapConfig}
        selectableTokens={pool.poolTokens.filter(token => token.symbol !== tokenIn.symbol)}
        isHighlighted={queryResponse?.swapKind === SwapKind.GivenIn}
      />
      <TokenField
        label="Token Out"
        token={tokenOut}
        pool={pool}
        userBalance={tokenBalances[tokenOut.address]}
        value={swapConfig.tokenOut.amount}
        onAmountChange={value => handleTokenAmountChange(value, "tokenOut")}
        setSwapConfig={setSwapConfig}
        selectableTokens={pool.poolTokens.filter(token => token.symbol !== tokenOut.symbol)}
        isHighlighted={queryResponse?.swapKind === SwapKind.GivenOut}
      />
      <UserDataInput onChange={handleUserDataChange} value={userDataInputValue} />

      {!queryResponse || isFormEmpty || swapReceipt ? (
        <TransactionButton
          label="Query"
          onClick={handleQuerySwap}
          isDisabled={isQueryFetching}
          isFormEmpty={isFormEmpty}
        />
      ) : !sufficientAllowance ? (
        <TransactionButton label={`Approve ${tokenIn.symbol}`} isDisabled={isApprovePending} onClick={handleApprove} />
      ) : (
        <TransactionButton label="Swap" isDisabled={isSwapPending} onClick={handleSwap} />
      )}

      {error && (
        <Alert type="error">
          {error.message.includes("0x340a4533")
            ? "The swap amount is too large for this pool. Try a smaller amount to avoid exceeding the pool's invariant ratio limits."
            : error.message}
        </Alert>
      )}

      {queryResponse && (
        <ResultsDisplay
          label={`Expected Amount ${queryResponse?.swapKind === SwapKind.GivenIn ? "Out" : "In"}`}
          data={[
            {
              symbol: queryResponse?.swapKind === SwapKind.GivenIn ? tokenOut.symbol : tokenIn.symbol,
              name: queryResponse?.swapKind === SwapKind.GivenIn ? tokenOut.name : tokenIn.name,
              decimals: queryResponse?.swapKind === SwapKind.GivenIn ? tokenOut.decimals : tokenIn.decimals,
              rawAmount:
                queryResponse?.swapKind === SwapKind.GivenIn
                  ? queryResponse.expectedAmountOut.amount
                  : queryResponse.expectedAmountIn.amount,
            },
          ]}
        />
      )}

      {swapReceipt && (
        <ResultsDisplay
          label={`Actual Amount ${swapConfig.swapKind === SwapKind.GivenIn ? "Out" : "In"}`}
          transactionHash={swapReceipt.transactionHash}
          data={swapConfig.swapKind === SwapKind.GivenIn ? [swapReceipt.data[0]] : [swapReceipt.data[1]]}
        />
      )}
    </section>
  );
};
