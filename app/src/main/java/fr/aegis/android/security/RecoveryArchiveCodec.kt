package fr.aegis.android.security

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/** Strict, bounded serialization for portable recovery records. */
object RecoveryArchiveCodec {
    data class Record(val id: String, val bytes: ByteArray)

    private val magic = byteArrayOf(0x41, 0x45, 0x47, 0x41) // AEGA
    private const val VERSION = 1
    private const val MAX_RECORDS = 1_024
    private const val MAX_RECORD_BYTES = 20 * 1024 * 1024
    const val MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
    private const val MAX_ID_BYTES = 80

    fun encode(records: List<Record>): ByteArray {
        require(records.size <= MAX_RECORDS) { "Trop d’enregistrements dans l’archive." }
        val ids = HashSet<String>()
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data ->
            data.write(magic)
            data.writeInt(VERSION)
            data.writeInt(records.size)
            records.forEach { record ->
                require(isAllowedId(record.id) && ids.add(record.id)) { "Identifiant d’enregistrement interdit ou dupliqué." }
                require(record.bytes.isNotEmpty() && record.bytes.size <= MAX_RECORD_BYTES) { "Enregistrement vide ou trop volumineux." }
                val id = record.id.toByteArray(Charsets.UTF_8)
                require(id.size in 1..MAX_ID_BYTES) { "Identifiant trop long." }
                data.writeByte(id.size)
                data.write(id)
                data.writeInt(record.bytes.size)
                data.write(record.bytes)
                require(output.size() <= MAX_ARCHIVE_BYTES) { "Archive de récupération supérieure à 20 Mio." }
            }
        }
        return output.toByteArray()
    }

    fun decode(bytes: ByteArray): List<Record> {
        require(bytes.size in 12..MAX_ARCHIVE_BYTES) { "Archive de récupération invalide ou trop volumineuse." }
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val header = ByteArray(magic.size)
        input.readFully(header)
        require(header.contentEquals(magic)) { "Signature d’archive inconnue." }
        require(input.readInt() == VERSION) { "Version d’archive non prise en charge." }
        val count = input.readInt()
        require(count in 0..MAX_RECORDS) { "Nombre d’enregistrements invalide." }
        val ids = HashSet<String>()
        val result = ArrayList<Record>(count)
        repeat(count) {
            val idLength = input.readUnsignedByte()
            require(idLength in 1..MAX_ID_BYTES) { "Longueur d’identifiant invalide." }
            val idBytes = ByteArray(idLength)
            input.readFully(idBytes)
            val id = idBytes.toString(Charsets.UTF_8)
            idBytes.fill(0)
            require(isAllowedId(id) && ids.add(id)) { "Identifiant interdit ou dupliqué." }
            val size = input.readInt()
            require(size in 1..MAX_RECORD_BYTES && size <= input.available()) { "Taille d’enregistrement invalide." }
            val payload = ByteArray(size)
            input.readFully(payload)
            result.add(Record(id, payload))
        }
        require(input.available() == 0) { "Données supplémentaires après l’archive." }
        return result
    }

    fun isAllowedId(id: String): Boolean =
        id.matches(Regex("chat_[A-Za-z0-9_-]{1,76}")) ||
            id.matches(Regex("received_[A-Za-z0-9_-]{1,70}"))

}
