open System
open System.IO
open System.Security.Cryptography

let bytesToHex bytes = 
    bytes 
    |> Array.map (fun (x : byte) -> System.String.Format("{0:X2}", x))
    |> String.concat System.String.Empty

let chunk chunkSize (arr : _ array) = 
    query {
        for idx in 0..(arr.Length - 1) do
        groupBy (idx / chunkSize) into g
        select (g |> Seq.map (fun idx -> arr.[idx]))
    } |> Seq.map (fun x -> Seq.toArray x)
    |> Seq.toArray

let printAt (n:int) (bs:byte[]): unit =
    let cs = chunk n bs
    cs |> Array.iter (fun a -> printfn "%s" (bytesToHex a))

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
    parts |> Seq.map (fun x -> x.Split('=')) |> Seq.map (fun ps -> (ps.[0], ps.[1])) |> Seq.toArray

let encodeCookie (map:List<string *string>) : (string) =
    map
    |> Seq.map (fun (k, v) ->
        let key = k.Replace("&", "").Replace("=", "")
        let value = v.Replace("&", "").Replace("=", "")
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

let encryptProfile (key:byte[]) (map:List<string * string>) : (byte[]) =
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

let decryptProfile (key:byte[]) (bytesToDecrypt:byte[]) : (string * string)[]  =
    let blockSize = 16
    let iv = Array.zeroCreate<byte> blockSize
    let decryptedBytes = decryptAesEcb key iv bytesToDecrypt
    printAt 16 decryptedBytes
    let decryptedText = decryptedBytes |> toText 
    let decryptedCookie = decodeCookie decryptedText
    decryptedCookie
    
let random = new Random(271)
let aesKey = randomAesKey random
let profile = [("email","foo@bar.com"); ("uid","10"); ("role","user")]
let encryptedProfile = encryptProfile aesKey profile

let decryptedProfile = decryptProfile aesKey encryptedProfile

let profileFor (email:string) : (string) =
    let profile = [("email",email); ("uid","10"); ("role","user")] // |> Map.ofSeq
    encodeCookie profile

let getEncryptedProfile (email:string) : (byte[]) =
    let profile = profileFor email
    encryptProfile2 aesKey profile



    // ECB Cut-and-Paste
let createAdminRole (getEncryptedProfile:string -> byte[]) =

    // 'email=foo@barba.'
    // 'com&uid=10&role='
    // 'user'
    let t0 = "foo@barba.com"
    let b0 = getEncryptedProfile t0

    printfn "'%s'" t0
    printAt 16 b0
    printfn "%d" b0.Length

    printfn ""


    


    // 'email=adminarba.'
    // 'admin           '
    // 'com&uid=10&role='
    // 'user'

    //let t1 = "foo@barba." + "admin           " + "com"
    let t1 = "foo@barba." + ("admin" + new String(char(12uy), 16 - 5)) + "com"
    let b1 = getEncryptedProfile t1
    printfn "'%s'" t1
    printAt 16 b1
    printfn "%d" b1.Length
    

    // email=adminarba.
    let firstBlock = Array.sub b0 0 16
    // com&uid=10&role=
    let secondBlock = Array.sub b0 16 16
    // admin
    let thirdBlock = Array.sub b1 16 16

    let hack = Array.concat [firstBlock; secondBlock; thirdBlock]

    printfn "%A"  (decryptProfile aesKey b0)
    printfn "%A"  (decryptProfile aesKey hack)

let doit () =
    createAdminRole (getEncryptedProfile)