package de.nerixyz.insta.decoders

import burp.*
import de.nerixyz.insta.*

/**
 * match a Signature (hex.{data})
 */
private val SIGNATURE_REGEX = Regex("^([a-fA-F\\d]+|SIGNATURE)\\.(.+)\$")

/**
 * Decodes everything on i.instagram.com
 */
class IgApiDecoder : MessageDecoder("i.instagram.com") {
    override fun onRequest(request: IRequestInfo, rawData: ByteArray): String? {
        val requestParts = arrayListOf<String>()
        if (request.bodyOffset < rawData.size - 1) {
            val signedInfo = request.parameters.findBodyParam("signed_body")
            if (signedInfo != null && SIGNATURE_REGEX.matches(signedInfo.value)) {
                val (signature, body) = SIGNATURE_REGEX.find(signedInfo.value)!!.destructured
                requestParts.add(signature.urlDecode())
                requestParts.add(body.urlDecode().jsonPrettyPrint())
            }
            requestParts.add(request.parameters.streamAllBodyParams().filter { it.name != "signed_body" }.toJson())
        } else {
            requestParts.add(request.parameters.streamAllUrlParams().toJson())
        }
        return requestParts.joinToString("\n")
    }
}