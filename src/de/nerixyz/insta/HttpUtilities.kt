package de.nerixyz.insta

import burp.IParameter
import burp.IResponseInfo
import java.nio.charset.StandardCharsets
import java.util.stream.Stream

fun List<IParameter>.find(type: Byte, name: String): IParameter? =
        this.stream().filter { it.type == type && it.name == name }.findFirst().orElse(null)

fun List<IParameter>.findBodyParam(name: String) = this.find(IParameter.PARAM_BODY, name)

fun List<IParameter>.streamAllUrlParams(): Stream<IParameter> = this.stream().filter { it.type == IParameter.PARAM_URL }
fun List<IParameter>.streamAllBodyParams(): Stream<IParameter> = this.stream().filter { it.type == IParameter.PARAM_BODY }

fun IResponseInfo.jsonPrettyPrint(data: ByteArray): String =
        String(data.copyOfRange(this.bodyOffset, data.size), StandardCharsets.UTF_8).jsonPrettyPrint()