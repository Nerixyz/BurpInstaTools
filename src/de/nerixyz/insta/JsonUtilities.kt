package de.nerixyz.insta

import burp.IParameter
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import java.util.stream.Stream

private val gsonInstance = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()
fun String.jsonPrettyPrint(): String = gsonInstance.toJson(JsonParser.parseString(this))

fun Stream<IParameter>.toJson(): String {
    val obj = JsonObject()
    this.forEach { obj.add(it.name.urlDecode(), JsonPrimitive(it.value.urlDecode())) }
    return gsonInstance.toJson(obj)
}