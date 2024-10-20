package dev.kwasi.echoservercomplete.network

import android.util.Log
import com.google.gson.Gson
import dev.kwasi.echoservercomplete.getFirstNChars
import dev.kwasi.echoservercomplete.models.ContentModel
import dev.kwasi.echoservercomplete.toHex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Exception
import kotlin.concurrent.thread
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.text.Charsets.UTF_8

/// The [Server] class has all the functionality that is responsible for the 'server' connection.
/// This is implemented using TCP. This Server class is intended to be run on the GO.
private val studentIDList = arrayOf(
    816111111,
    816222222,
    816333333,
    816444444,
    816555555,
    816666666,
    816777777,
    816888888,
    816999999,
    816117992,
    816033593
)

private var isverfied = false
private var seed = " "
private var clientIp = " "


class Server(private val iFaceImpl:NetworkMessageInterface) {
    companion object {
        const val PORT: Int = 9999

    }

    private val svrSocket: ServerSocket = ServerSocket(PORT, 0, InetAddress.getByName("192.168.49.1"))
    private val clientMap: HashMap<String, Socket> = HashMap()

    init {
        thread{
            while(true){
                try{
                    val clientConnectionSocket = svrSocket.accept()
                    Log.e("SERVER", "The server has accepted a connection: ")
                    handleSocket(clientConnectionSocket)

                }catch (e: Exception){
                    Log.e("SERVER", "An error has occurred in the server!")
                    e.printStackTrace()
                }
            }
        }
    }


    @OptIn(ExperimentalEncodingApi::class)
    private fun handleSocket(socket: Socket){
        socket.inetAddress.hostAddress?.let {
            clientMap[it] = socket
            clientIp = it
            Log.e("SERVER", "A new connection has been detected!")
            thread {
                val clientReader = socket.inputStream.bufferedReader()
                val clientWriter = socket.outputStream.bufferedWriter()
                var receivedJson: String?

                while(socket.isConnected){
                    try{
                        receivedJson = clientReader.readLine()
                        if (receivedJson!= null){
                            Log.e("SERVER", "Received a message from client $it")
                            val clientContent = Gson().fromJson(receivedJson, ContentModel::class.java)
                            if(clientContent.message=="I am here"){
                                Log.e("SERVER", "get i am here")
                                val rStr = generateR().toString()
                                //clientIp = clientContent.senderIp
                                Log.e("SERVER", "Client IP: $clientIp")
                                val serverContent = ContentModel(rStr,"192.18.49.1")
                                val serverContentStr = Gson().toJson(serverContent)

                                clientWriter.write("$serverContentStr\n")
                                clientWriter.flush()
                                var noRes: Boolean = true
                                while(noRes){
                                    receivedJson = clientReader.readLine()
                                    if(receivedJson!=null){
                                        val clientEncryption = Gson().fromJson(receivedJson, ContentModel::class.java)
                                        noRes = false
                                        Log.e("SERVER", "received encrypted $rStr")
                                        for (studentID in studentIDList) {
                                            val tempStr=hashStrSha256(studentID.toString())
                                            val msg = clientEncryption.message
                                            val aesKey = generateAESKey(tempStr)
                                            val aesIv = generateIV(tempStr)
                                            Log.e("SERVER", "Attempting decryption with student ID: $studentID")
                                            Log.e("SERVER", "Encrypted Message: $msg")
                                            val tempcheck = encryptMessage(rStr, aesKey, aesIv)
                                            Log.e("SERVER", "Encrypted Message: $tempcheck")
                                            //val valid=verifyR(rStr, studentID.toString(), msg)
                                            //val maybeR=decryptMessage(msg, aesKey, aesIv)
//                                            Log.e("SERVER", maybeR)
                                            if(tempcheck==msg){
                                                seed = tempStr
                                                isverfied = true
                                                Log.e("SERVER", "GET TRU")
                                                break
                                            }
                                        }
                                    }
                                }
                            }
                            else {

                                //Log.e("SERVER", "Finish protocol")

                                if (isverfied) {
                                    Log.e("SERVER", "decrypting msg")
                                    val aesKey = generateAESKey(seed.toString())
                                    val aesIv = generateIV(seed.toString())
                                    val msg = decryptMessage(clientContent.message, aesKey, aesIv)
                                    val clientContentDecrypt = ContentModel(msg, "192.168.49.1")
                                    iFaceImpl.onContent(clientContentDecrypt)
                                }
                            }
                            //val reversedContent = ContentModel(clientContent.message.reversed(), "192.168.49.1")

//                            val reversedContentStr = Gson().toJson(reversedContent)
//                            clientWriter.write("$reversedContentStr\n")
//                            clientWriter.flush()

                            // To show the correct alignment of the items (on the server), I'd swap the IP that it came from the client
                            // This is some OP hax that gets the job done but is not the best way of getting it done.
//                            val tmpIp = clientContent.senderIp
//                            clientContent.senderIp = reversedContent.senderIp
//                            reversedContent.senderIp = tmpIp


                            //iFaceImpl.onContent(reversedContent)

                        }
                    } catch (e: Exception){
                        Log.e("SERVER", "An error has occurred with the client $it")
                        e.printStackTrace()
                    }
                }
            }
        }
    }

    fun close(){
        svrSocket.close()
        clientMap.clear()
    }

    private fun logClientMap() {
        Log.e("SERVER", "Current clientMap contents:")
        for ((ip, socket) in clientMap) {
            Log.e("SERVER", "Client IP: $ip, Socket: $socket")
        }
    }

    fun sendMessageToClient(message: ContentModel) {
        val socket = clientMap[clientIp]
        if (socket == null) {
            Log.e("SERVER", "No socket found for IP: $clientIp")
            return
        }
        val aesKey = generateAESKey(seed)
        val aesIv = generateIV(seed)
        val msg = encryptMessage(message.message, aesKey, aesIv)
        val encryptedServerMsg = ContentModel(msg, message.senderIp)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val clientWriter = socket.outputStream.bufferedWriter()
                val messageStr = Gson().toJson(encryptedServerMsg)
                clientWriter.write("$messageStr\n")
                clientWriter.flush()
                Log.e("SERVER", "Message sent to client: $clientIp")
            } catch (e: Exception) {
                Log.e("SERVER", "Failed to send message to client $clientIp")
                e.printStackTrace()
            }
        }
    }


    private fun hashStrSha256(str: String): String{
        val algorithm = "SHA-256"
        val hashedString = MessageDigest.getInstance(algorithm).digest(str.toByteArray(UTF_8))
        return hashedString.toHex();
    }

    private fun generateAESKey(seed: String): SecretKeySpec {
        val first32Chars = getFirstNChars(seed,32)
        val secretKey = SecretKeySpec(first32Chars.toByteArray(), "AES")
        return secretKey
    }

    private fun generateIV(seed: String): IvParameterSpec {
        val first16Chars = getFirstNChars(seed, 16)
        return IvParameterSpec(first16Chars.toByteArray())
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encryptMessage(plaintext: String, aesKey: SecretKey, aesIv: IvParameterSpec):String{
        val plainTextByteArr = plaintext.toByteArray()
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv)
        val encrypt = cipher.doFinal(plainTextByteArr)
        return Base64.Default.encode(encrypt)
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun decryptMessage(encryptedText: String, aesKey: SecretKey, aesIv: IvParameterSpec):String{
        val textToDecrypt = Base64.Default.decode(encryptedText)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, aesKey,aesIv)
        val decrypt = cipher.doFinal(textToDecrypt)
        return String(decrypt)
    }

    private fun generateR(): Int
    {
        return Random.nextInt()
    }

    private fun getEncryption(R: String, seed: String): String
    {
        val strongSeed = hashStrSha256(seed)
        val aesKey = generateAESKey(strongSeed)
        val aesIV = generateIV(strongSeed)

        Log.e("CA", "Random number: $R")
        Log.e("CA", seed)

        return encryptMessage(R, aesKey, aesIV)
    }

    private fun verifyR(R: String, id: String, encryption: String): Boolean
    {
        val seed = id
        val strongSeed = hashStrSha256(seed)
        val aesKey = generateAESKey(strongSeed)
        val aesIV = generateIV(strongSeed)

        val decryption = decryptMessage(encryption, aesKey, aesIV)

        return (R == decryption)
    }

    private fun encryptTest()
    {
        val R = generateR()
        val encryption = getEncryption(R.toString(), studentIDList[9].toString())

        Log.e("CA", "Encrypted message: $encryption")

        val res = verifyR(R.toString(), studentIDList[9].toString(), encryption)

        if(res)
        {
            Log.e("CA", "Decryption successful")
        }
        else
        {
            Log.e("CA", "Decryption unsuccessful")
        }
    }

    fun lookupID(id: Int): Boolean
    {
        for(s in studentIDList)
        {
            if(id == s) return true
        }

        return false
    }

}