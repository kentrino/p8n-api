import {
  CertificateContent_JPKICardDigitalSignatureContent,
  CertificateStatus_CheckMethod,
  Verification_HashAlgorithm,
} from "@buf/pocketsign_apis.bufbuild_es/pocketsign/verify/v2/types_pb"
import { VerificationService } from "@buf/pocketsign_apis.connectrpc_es/pocketsign/verify/v2/verification_connect"
import { PromiseClient, createPromiseClient } from "@connectrpc/connect"
import { createConnectTransport } from "@connectrpc/connect-web"
import { z } from "zod"

const bodySchema = z.object({
  signature: z.string(),
  digest: z.string(),
  certificate: z.string(),
  document: z.string().nullish(),
})

export async function POST(request: Request) {
  const token = process.env.POCKET_SIGN_API_KEY
  if (!token) {
    return Response.json({ success: false, message: "Missing token" }, { status: 500 })
  }
  const endpoint = "https://verify.mock.p8n.app"
  const body = await request.json()
  const result = bodySchema.safeParse(body)
  if (!result.success) {
    return Response.json(
      {
        success: false,
        message: "Invalid request body",
      },
      { status: 400 },
    )
  }
  const { signature, digest, certificate } = result.data
  try {
    const client: PromiseClient<typeof VerificationService> = createPromiseClient(
      VerificationService,
      createConnectTransport({
        baseUrl: endpoint,
        useBinaryFormat: true,
      }),
    )
    const result = await client.verify(
      {
        certificate: Buffer.from(certificate, "base64"),
        digest: Buffer.from(digest, "base64"),
        signature: Buffer.from(signature, "base64"),
        hashAlgorithm: Verification_HashAlgorithm.SHA256,
        // デフォルトはCRL。確実に当日分の失効情報を確認したい場合はOSCPを使うと良い
        // cf. https://docs.p8n.app/docs/verify/guide/api/check-method
        checkMethod: CertificateStatus_CheckMethod.CRL,
        // リクエスト時に `identify_user` を `true` にした場合、CertificateContentが返却される
        identifyUser: true,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    )
    const value = result.certificateContent?.typeSpecificContent?.value
    if (!value) {
      return Response.json({
        success: false,
        message: `CertificateContent is unexpectedly empty`,
      })
    }
    // FIXME: ほかのClassのハンドリング
    if (
      value.getType().typeName ===
      "pocketsign.verify.v2.CertificateContent.JPKICardDigitalSignatureContent"
    ) {
      const v = value as CertificateContent_JPKICardDigitalSignatureContent
      return Response.json({
        success: true,
        result: {
          commonName: v.commonName,
          gender: v.gender,
          dateOfBirth: v.dateOfBirth,
          address: v.address,
          substituteCharacterOfAddress: v.substituteCharacterOfAddress,
          substituteCharacterOfCommonName: v.substituteCharacterOfCommonName,
        },
        message: `success`,
      })
    }
  } catch (e) {
    return Response.json(
      {
        success: false,
        message: `Error: ${(e as Error).message}`,
      },
      { status: 400 },
    )
  }
}
