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

let base64Decode (text:string) : (byte []) =
    let rec decodeBytes chars =
        match chars with
        | [] -> []
        | a::b::c::d::xs ->
            let bytes = (getBytes a b c d) |> Seq.toList
            bytes @ (decodeBytes xs)
        | _ -> invalidArg "chars" "Bytes must be multiple of 4 in length"
    let chars = text.ToCharArray() |> Array.toList
    let bytes = decodeBytes chars
    bytes |> List.toArray

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

type EncryptionType =
    | ECB
    | CBC

let randomBytes (r:Random) (n:int) =
    let bytes = Array.zeroCreate n
    r.NextBytes bytes
    bytes

let randomAesKey (r:Random) =
    randomBytes r 16 

let r = new Random (271)

let randomEcbKey = randomBytes r 16

let unknownBase64Text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

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

let encrypt (bytes: byte[]) : (byte []) =
    let unknownBytes = base64Decode unknownBase64Text
    let bytesToEncrypt = [bytes;unknownBytes] |> Array.concat 
    let blockSize = 16
    let iv = Array.zeroCreate<byte> blockSize
    encryptAesEcb randomEcbKey iv bytesToEncrypt

let detectEcbOrCbc (bytes:byte []) (blockSize: byte) : (EncryptionType) =
    let blocks = chunk (int(blockSize)) bytes
    let setBlocks = blocks |> Set.ofSeq
    let setLength = setBlocks |> Set.count
    let blocksLength = blocks |> Seq.length
    match setLength = blocksLength with
    | true -> CBC
    | false -> ECB

let detectBlockSize encrypt =
    // guess block sizes 2 - 40 bytes (16 - 320 bits)
    let blockSizes = [|2..40|]
    let userBytes = blockSizes |> Array.map (fun blockSize -> Array.create blockSize (byte('A')))

    let ts =
        userBytes
        |> Array.map (fun userBytes -> (userBytes |> Array.length, encrypt userBytes |> Array.length))
    let (ul0, el0) = ts.[0]
    let (restBlockSize, restEncryptedLength) = ts |> Seq.find (fun (cul0, cel0) -> cel0 > el0)
    let (blockSize, _) = ts |> Seq.find (fun (cul0, cel0) -> (cel0 - restEncryptedLength) > restBlockSize)
    blockSize - restBlockSize

let ensureIsEcbMode blockSize : (unit) =
    // need 3 blocks of repeated bytes to get a repeated block
    let encryptedText = encrypt (Array.create (blockSize * 3) (byte('A')))
    // detect mode (should be ECB)
    let mode = detectEcbOrCbc encryptedText (byte(blockSize))
    match mode with
    | CBC -> failwith "Cannot decrypt CBC message"
    | ECB -> ()

let getMap plaintextBytes offset blockSize =
    plaintextBytes
    |> Array.map (fun plaintextBytes ->
        let encryptedText = encrypt plaintextBytes
        let selectedBytes = Array.sub encryptedText offset blockSize
        let lastByte = plaintextBytes.[plaintextBytes.Length - 1]
        (selectedBytes, lastByte))
    |> Map.ofArray

let getSecretBytes blockSize blockCount =
    let blockNumbers = [|0..blockCount|]
    let ts =
        blockNumbers |> Array.map (fun blockNumber ->
            let paddingSizes = [|1..blockSize|]
            paddingSizes |> Array.map (fun paddingSize -> (blockNumber, paddingSize)))
        |> Array.concat

    ts |> Array.fold (fun (secretBytes:byte[]) ((blockNumber, paddingSize:int):(int*int)) ->
        let blockSuffixes = [|0uy..255uy|]
        let prefixLength = blockSize - paddingSize
        let paddingByte = 0uy
        let blockPrefix = Array.create prefixLength paddingByte
        let plaintextBytes =
            blockSuffixes
            |> Array.map (fun blockSuffix -> [blockPrefix;secretBytes;[|blockSuffix|]] |> Array.concat)
        let offset = blockNumber * blockSize
        let bytesByEncryptedBlock = getMap plaintextBytes offset blockSize
        let encryptedBlock =
            let encryptedBytes = encrypt blockPrefix
            Array.sub encryptedBytes offset blockSize
        let secretByte =
            match Map.tryFind encryptedBlock bytesByEncryptedBlock with
            // HACK: Cannot figure out how to exit nicely here. Just failwith the secret text
            | None -> failwith (secretBytes |> toText)
            | Some b -> b
        [|secretBytes;[|secretByte|]|] |> Array.concat) [||]

let doit () =
    let detectedBlockSize = detectBlockSize encrypt
    ensureIsEcbMode detectedBlockSize

    // encrypt empty message to determine secret padding text block count
    let unknownTextBlockCount = encrypt ([||]:byte []) |> Array.length |> (fun l -> l / detectedBlockSize)
    let someSecretBytes = getSecretBytes detectedBlockSize unknownTextBlockCount
    toText someSecretBytes
