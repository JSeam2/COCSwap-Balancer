import {
  ExactInQueryOutput,
  ExactOutQueryOutput,
  MaxAllowanceExpiration,
  PermitDetails, //  Permit2Helper,
  Slippage,
  Swap,
  SwapInput,
} from "@balancer/sdk";
import { useMutation } from "@tanstack/react-query";
import { useWalletClient } from "wagmi";
import { useTransactor } from "~~/hooks/scaffold-eth";
import { useAllowanceOnPermit2, useSignPermit2 } from "~~/hooks/token";

export const useSwap = (swapInput: SwapInput | null) => {
  // Always call hooks at the top level, regardless of input
  const { data: walletClient } = useWalletClient();
  const writeTx = useTransactor();
  const { signPermit2 } = useSignPermit2();

  // Handle null swapInput by using a fallback address
  // Using zeroAddress as a fallback which is a safe value for tokens that won't be used
  const tokenInAddress = swapInput?.paths[0]?.tokens[0].address || "0x0000000000000000000000000000000000000000";
  const { data, refetch: refetchAllowanceOnPermit2 } = useAllowanceOnPermit2(tokenInAddress);

  // Create a single mutation instance that handles both the null and non-null cases
  return useMutation({
    mutationFn: async (queryOutput: ExactInQueryOutput | ExactOutQueryOutput | undefined) => {
      // Handle null swapInput
      if (!swapInput) {
        throw new Error("Cannot swap with null input");
      }

      const tokenIn = swapInput.paths[0].tokens[0];
      const amountIn = swapInput.paths[0].inputAmountRaw;
      const allowanceOnPermit2 = data?.[0];
      const nonce = data?.[2];
      const swap = new Swap(swapInput);

      if (!walletClient) throw new Error("Must connect a wallet to send a transaction");
      if (!queryOutput) throw new Error("Query output is required to swap");

      const deadline = 999999999999999999n; // Deadline for the swap, in this case infinite
      // Increase slippage to 1% to handle potential invariant ratio constraints
      const slippage = Slippage.fromPercentage("1.0"); // 1.0%
      const buildCallInput = {
        slippage,
        deadline,
        queryOutput,
        wethIsEth: false,
      };

      let call;

      if (allowanceOnPermit2 !== undefined && allowanceOnPermit2 < amountIn) {
        if (nonce === undefined) throw new Error("Nonce is required to sign the permit");

        const details: PermitDetails[] = [
          {
            token: tokenIn.address,
            amount: amountIn,
            expiration: Number(MaxAllowanceExpiration),
            nonce,
          },
        ];
        const permit2 = await signPermit2(walletClient, details);

        call = swap.buildCallWithPermit2(buildCallInput, permit2);
      } else {
        call = swap.buildCall(buildCallInput);
      }

      const txHashPromise = () =>
        walletClient.sendTransaction({
          account: walletClient.account,
          data: call.callData,
          to: call.to,
          value: call.value,
        });

      const txHash = await writeTx(txHashPromise, { blockConfirmations: 1 });
      if (!txHash) throw new Error("Transaction failed");

      refetchAllowanceOnPermit2();

      return txHash;
    },
  });
};
