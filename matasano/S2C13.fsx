open System
open System.IO
open System.Security.Cryptography

let toByte (char:char) : (byte) =
    byte(char)
let toBytes (chars:char seq) : (byte seq) =
    chars |> Seq.map toByte

let toChar (byte:byte) : (char) =
    char(byte)
let toChars (bytes:byte seq) : (char seq) =
    bytes |> Seq.map toChar

let toText (bytes:byte seq) : (string) =
    bytes |> toChars |> String.Concat

// foo=bar&baz=qux&zap=zazzle
let decodeCookie (text:string) = 
    let parts = text.Split('&')
    parts |> Seq.map (fun x -> x.Split('=')) |> Seq.map (fun ps -> (ps.[0], ps.[1])) |> Map.ofSeq

let encodeCookie (map:Map<string,string>) : (string) =
    map
    |> Seq.map (fun kvp ->
        let key = kvp.Key.Replace("&", "").Replace("=", "")
        let value = kvp.Value.Replace("&", "").Replace("=", "")
        key + "=" + value)
    |> Seq.reduce (fun a b -> a + "&" + b)

let randomBytes (r:Random) (n:int) =
    let bytes = Array.zeroCreate n
    r.NextBytes bytes
    bytes

let randomAesKey (r:Random) =
    randomBytes r 16 

let pkcs7 (blockSize:byte) (bytes:byte []) =
    let extra = bytes.Length % int(blockSize)
    if (extra = 0)
    then bytes
    else
        let paddingCount = int(blockSize) - extra
        let paddingByte = byte(paddingCount)
        (bytes |> Array.toList) @ (List.replicate paddingCount paddingByte) |> List.toArray

let encryptAesEcb (keyBytes:byte []) (iv:byte []) (bytes:byte []) =
    let blockSize = iv.Length
    let paddedBytes = pkcs7 (byte(blockSize)) bytes
    let aes = Aes.Create()
    aes.BlockSize <- blockSize * 8
    aes.Mode <- CipherMode.ECB
    aes.Key <- keyBytes
    aes.IV <- iv
    aes.Padding <- PaddingMode.None

    let data = Array.zeroCreate<byte> (paddedBytes.Length)
    use stream = new MemoryStream(data)
    use encryptor = aes.CreateEncryptor()
    use cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write)
    cryptoStream.Write(paddedBytes, 0, paddedBytes.Length)
    cryptoStream.FlushFinalBlock()
    data

let decryptAesEcb (keyBytes:byte []) (iv:byte []) (bytes:byte []) =
    let aes = Aes.Create()
    aes.BlockSize <- iv.Length * 8
    aes.Mode <- CipherMode.ECB
    aes.Key <- keyBytes
    aes.IV <- iv
    aes.Padding <- PaddingMode.None

    let result = Array.zeroCreate<byte> (bytes.Length)
    use stream = new MemoryStream(bytes)
    use decryptor = aes.CreateDecryptor()
    use cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read)
    let bytesRead = cryptoStream.Read(result, 0, bytes.Length)
    result

let encryptProfile (key:byte[]) (map:Map<string,string>) : (byte[]) =
    let blockSize = 16
    let iv = Array.zeroCreate<byte> blockSize
    let encodedCookie = encodeCookie map
    let bytesToEncrypt = encodedCookie.ToCharArray() |> toBytes |> Seq.toArray
    encryptAesEcb key iv bytesToEncrypt

let encryptProfile2 (key:byte[]) (text:string) : (byte[]) =
    let blockSize = 16
    let iv = Array.zeroCreate<byte> blockSize
    let bytesToEncrypt = text |> toBytes |> Seq.toArray
    encryptAesEcb key iv bytesToEncrypt

let decryptProfile (key:byte[]) (bytesToDecrypt:byte[]) : (Map<string,string>) =
    let blockSize = 16
    let iv = Array.zeroCreate<byte> blockSize
    let decryptedBytes = decryptAesEcb key iv bytesToDecrypt
    let decryptedText = decryptedBytes |> toText 
    let decryptedCookie = decodeCookie decryptedText
    decryptedCookie
    
let random = new Random(271)
let aesKey = randomAesKey random
let profile = [("email","foo@bar.com"); ("uid","10"); ("role","user")] |> Map.ofSeq
let encryptedProfile = encryptProfile aesKey profile

let decryptedProfile = decryptProfile aesKey encryptedProfile

let profileFor (email:string) : (string) =
    let profile = [("email",email); ("uid","10"); ("role","user")] |> Map.ofSeq
    encodeCookie profile

let getEncryptedProfile (email:string) : (byte[]) =
    let profile = profileFor email
    encryptProfile2 aesKey profile

let createAdminRole (getEncryptedProfile:string -> byte[])=
    // TODO: loop here
    let email = ""
    let cipherText = getEncryptedProfile email
    let adminRoleCiphertext = cipherText
    // end loop here

    let adminRoled = decryptProfile aesKey adminRoleCiphertext
    adminRoled

let doit () =
    createAdminRole (getEncryptedProfile)