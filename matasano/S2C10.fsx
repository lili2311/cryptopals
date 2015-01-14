open System
open System.IO
open System.Security.Cryptography

let getByte (c:char) : (byte) =
    match c with
    | _ when c >= 'A' && c <= 'Z' -> byte(c) - byte('A')
    | _ when c >= 'a' && c <= 'z' -> byte(c) - (byte('a') - 26uy)
    | _ when c >= '0' && c <= '9' -> byte(c) - (byte('0') - 52uy)
    | '+' -> 62uy
    | '/' -> 63uy
    | _ -> invalidArg "c" "c must be [0-63]"

let getBytes (c0:char) (c1:char) (c2:char) (c3:char) : (byte seq) =
    match (c0, c1, c2, c3) with
    | (a,b,c,d) when c = '=' && d = '=' ->
        let b0 = (getByte a <<< 2) ||| (getByte b >>> 4)
        seq [ b0 ]

    | (a,b,c,d) when d = '=' ->
        let b0 = (getByte a <<< 2) ||| (getByte b >>> 4)
        let b1 = (getByte b <<< 4) |||  (getByte c >>> 2)
        seq [ b0; b1 ]

    | (a,b,c,d) -> 
        let b0 = (getByte a <<< 2) ||| (getByte b >>> 4)
        let b1 = (getByte b <<< 4) ||| (getByte c >>> 2)
        let b2 = (getByte c <<< 6) ||| (getByte d)
        seq [ b0; b1; b2 ]

let base64Decode (text:string) : (byte list) =
    let rec decodeBytes chars =
        match chars with
        | [] -> []
        | a::b::c::d::xs ->
            let bytes = (getBytes a b c d) |> Seq.toList
            bytes @ (decodeBytes xs)
        | _ -> invalidArg "chars" "Bytes must be multiple of 4 in length"
    let chars = text.ToCharArray() |> Array.toList
    let bytes = decodeBytes chars
    bytes

let toChar (byte:byte) : (char) =
    char(byte)
let toChars (bytes:byte seq) : (char seq) =
    bytes |> Seq.map toChar

let toText (bytes:byte seq) : (string) =
    bytes |> toChars |> String.Concat

let escapeChars (chars:char seq) : (char seq) =
    chars |> Seq.map (fun c ->
        match c with
        | x when x >= ' ' && x <= '~' -> x
        | _ -> '?')

let escapeText (text:string) : (string) =
    text.ToCharArray() |> escapeChars |> String.Concat

let toByte (char:char) : (byte) =
    byte(char)
let toBytes (chars:char seq) : (byte seq) =
    chars |> Seq.map toByte

let pkcs7 (blockSize:byte) (bytes:byte []) =
    let extra = bytes.Length % int(blockSize)
    if (extra = 0)
    then bytes
    else
        let paddingCount = int(blockSize) - extra
        let paddingByte = byte(paddingCount)
        (bytes |> Array.toList) @ (List.replicate paddingCount paddingByte) |> List.toArray

// http://stackoverflow.com/questions/716452/f-array-chunk-for-sequence
let chunk n xs = seq {
    let i = ref 0
    let arr = ref <| Array.create n (Unchecked.defaultof<'a>)
    for x in xs do
        if !i = n then 
            yield !arr
            arr := Array.create n (Unchecked.defaultof<'a>)
            i := 0 
        (!arr).[!i] <- x
        i := !i + 1
    if !i <> 0 then
        yield (!arr).[0..!i-1] }

let xorBytes (bs0:byte []) (bs1:byte []) : (byte []) =
    Array.zip bs0 bs1 |> Array.map (fun (b0, b1) -> b0 ^^^ b1)

// http://failheap-challenge.com/showthread.php?12388-The-Matasano-crypto-challenges/page7
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

//let plainText = "The quick brown fox jumped over the lazy dogs"
//let key = "YELLOW SUBMARINE" |> toBytes |> Seq.toArray
//let iv = "0000000000000000" |> toBytes |> Seq.toArray
//let cipherText = encryptAesEcb key iv (plainText |> toBytes |> Seq.toArray)
//let decrypted = decryptAesEcb key iv cipherText
//let decryptedText = decrypted |> toText

let decryptAesCbc (key:byte []) (iv:byte []) (bytes:byte seq) : (byte [] seq) =
    let blockSize = iv.Length
    let blocks = Seq.append [iv] (chunk blockSize bytes)
    let data =
        blocks
        |> Seq.map (fun block ->
            let iv = Array.zeroCreate<byte> key.Length
            (decryptAesEcb key iv block, block))
        |> Seq.windowed 2
        |> Seq.map (fun xs ->
            let (_, prevCipherText) = xs.[0]
            let (currentDecryptedText, _) = xs.[1]
            let plainText = xorBytes prevCipherText currentDecryptedText
            plainText)
    data

let path = @"C:\Users\ryanj\Documents\GitHub\cryptopals\matasano\10.txt"
let result =
    let lines = System.IO.File.ReadAllLines path
    let bytes =
        lines
        |> Array.map (fun s -> base64Decode s |> List.toArray)
        |> Array.collect (fun x -> x)
    let key = "YELLOW SUBMARINE" |> toBytes |> Seq.toArray
    let iv = Array.create key.Length 0uy
    let decryptedBytes = decryptAesCbc key iv bytes
    let decryptedText =
        decryptedBytes
        |> Seq.collect (fun x -> x)
        |> toText
        |> escapeText
    decryptedText