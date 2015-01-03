open System

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

let key = "GAhjlIv53" |> toBytes |> Seq.toArray
let iv = "gdyrt[qv#" |> toBytes |> Seq.toArray
let plainText = "The quick brown fox jumped over the lazy dogs"
let plainTextBytes =
    plainText.ToCharArray()
    |> Array.map (fun c -> byte (c))

let encryptedBytes =
    cbcEncrypt key iv plainTextBytes
    |> Seq.toArray
    |> Array.collect (fun x -> x)
let encryptedText = encryptedBytes |> toText |> escapeText

let decryptedBytes =
    cbcDecrypt key iv encryptedBytes
    |> Seq.toArray
    |> Array.collect (fun x -> x)

let decryptedText =
    decryptedBytes
    |> Array.map (fun b -> char(b))
    |> String.Concat
    |> escapeText

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

// TODO: Figure out why cannot decode from file
let path = @"C:\Users\ryanj\Documents\GitHub\cryptopals\matasano\10.txt"
let doit path =
    let lines = System.IO.File.ReadAllLines path
    let bytes =
        lines
        |> Array.map (fun s -> base64Decode s |> List.toArray)
        |> Array.collect (fun x -> x)
    let key = "YELLOW SUBMARINE" |> toBytes |> Seq.toArray
    let iv = Array.create key.Length 0uy
    let decryptedBytes = cbcDecrypt key iv bytes
    let decryptedText =
        decryptedBytes
        |> Seq.collect (fun x -> x)
        |> toText
        |> escapeText
    decryptedText