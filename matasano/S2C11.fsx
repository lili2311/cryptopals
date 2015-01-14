
open System

let pkcs7 (blockSize:byte) (bytes:byte []) : (byte []) =
    let paddingCount = int(blockSize) - (bytes.Length % int(blockSize))
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

let xorEncrypt (key:byte []) (bytes:byte []) : (byte []) =
    let keyLength = key.Length
    bytes |> Array.mapi (fun i b -> key.[i % keyLength] ^^^ b)

let xorDecrypt (key:byte []) (bytes:byte []) : (byte []) =
    let keyLength = key.Length
    bytes |> Array.mapi (fun i b -> key.[i % keyLength] ^^^ b)

let xorBytes (bs0:byte []) (bs1:byte []) : (byte []) =
    Array.zip bs0 bs1 |> Array.map (fun (b0, b1) -> b0 ^^^ b1)

let ecbEncrypt (key:byte []) (bytes:byte seq) : (byte [] seq) =
    let blockSize = key.Length
    let blocks = chunk blockSize bytes
    let encryptBlock (key:byte []) (plainText:byte []) : (byte []) =
        xorEncrypt key plainText
    let data =
        blocks |> Seq.map (encryptBlock key)
    data

let ecbDecrypt (key:byte []) (bytes:byte seq) : (byte [] seq) =
    let blockSize = key.Length
    let blocks = chunk blockSize bytes
    let decryptBlock (key:byte []) (plainText:byte []) : (byte []) =
        xorDecrypt key plainText
    let data =
        blocks |> Seq.map (decryptBlock key)
    data

let cbcEncrypt (key:byte []) (iv:byte []) (bytes:byte seq) : (byte [] seq) =
    let blockSize = iv.Length
    let blocks = chunk blockSize bytes
    let encryptBlock (cipherText:byte []) (plainText:byte []) : (byte []) =
        let toEncrypt = xorBytes cipherText plainText
        xorEncrypt key toEncrypt
    let data =
        blocks |> Seq.scan (encryptBlock) iv
        // 1st block result is the IV; ignore it
        |> Seq.skip 1
    data

let cbcDecrypt (key:byte []) (iv:byte []) (bytes:byte seq) : (byte [] seq) =
    let blockSize = iv.Length
    let blocks = Seq.append [iv] (chunk blockSize bytes)
    let data =
        blocks
        |> Seq.map (fun c -> (xorDecrypt key c, c))
        |> Seq.windowed 2
        |> Seq.map (fun xs ->
            let (_, prevCipherText) = xs.[0]
            let (currentDecryptedText, _) = xs.[1]
            let plainText = xorBytes prevCipherText currentDecryptedText
            plainText)
    data

let randomBytes (r:Random) (n:int) =
    let bytes = Array.zeroCreate n
    r.NextBytes bytes
    bytes

let randomAesKey (r:Random) =
    randomBytes r 16 

let encryptRandom (r:Random) (bytes: byte []) : (byte []) =
    let key = randomAesKey r
    let prefix = randomBytes r (r.Next (5, 10))
    let postfix = randomBytes r (r.Next (5, 10))
    let bs = [prefix;bytes;postfix] |> Array.concat |> (pkcs7 16uy)
    let encryptedBytes =
        match (r.NextDouble () > 0.5) with
        | true -> ecbEncrypt key bs
        | false ->
            let iv = randomBytes r 16
            cbcEncrypt key iv bs
    encryptedBytes |> Seq.toArray |> Array.collect (fun x -> x)

type EncryptionType =
    | ECB
    | CBC

let toChars (bytes:byte seq) : (char seq) =
    let toChar (byte:byte) : (char) =
        char(byte)
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

let toBytes (chars:char seq) : (byte seq) =
    let toByte (char:char) : (byte) =
        byte(char)
    chars |> Seq.map toByte

let detectEcbOrCbc (plainText:byte seq) (bytes:byte seq) : (EncryptionType) =
    
let r = new Random(271)

//
//let doit (r:Random) =
//    let plainText = randomBytes r 1024
//    let encrypted = encryptRandom r plainText
//    detectEcbOrCbc encrypted

let key = "ghfncju8b#f1*-['"
let keyBytes = key |> toBytes |> Seq.toArray
let plainText = "The quick brown fox jumped over the lazy dogs"
let foo =
    |> toBytes
    |> Seq.toArray
    |> (xorEncrypt keyBytes)