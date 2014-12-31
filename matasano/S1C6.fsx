
open System

let hexToByte (h:char) : (byte) =
    match h with
    | '0' -> 0uy
    | '1' -> 1uy
    | '2' -> 2uy
    | '3' -> 3uy
    | '4' -> 4uy
    | '5' -> 5uy
    | '6' -> 6uy
    | '7' -> 7uy
    | '8' -> 8uy
    | '9' -> 9uy
    | 'A' -> 10uy
    | 'a' -> 10uy
    | 'B' -> 11uy
    | 'b' -> 11uy
    | 'C' -> 12uy
    | 'c' -> 12uy
    | 'D' -> 13uy
    | 'd' -> 13uy
    | 'E' -> 14uy
    | 'e' -> 14uy
    | 'F' -> 15uy
    | 'f' -> 15uy
    | _ -> invalidArg "h" "Value must be [0-9,A-F]"

let rec hexToBytes (cs:char list) : (byte list) =
    match cs with
    | [] -> []
    | x::y::ys -> [(((hexToByte x) <<< 4) ||| hexToByte y)] @ (hexToBytes ys)
    | [x] -> [(hexToByte x)]

let hexDecode (s:string) : (byte list) =
    s.ToCharArray() |> Array.toList |> hexToBytes

let byteToHex (byte:byte) : (string) = byte.ToString("X2")
let hexEncode (bytes:byte seq) : (string) =
    bytes |> Seq.collect byteToHex |> String.Concat

let byteToBase64 (b:byte) : (char) =
    match b with
    // [0-25] -> [A-Z]
    | l when l < 26uy ->  (char)(l + (byte)'A')
    // [26-51] -> [a-z]
    | l when l < 52uy ->  (char)(l - 26uy + (byte)'a')
    // [52-61] -> [0-9]
    | l when l < 62uy ->  (char)(l - 26uy  - 26uy + (byte)'0')
    // 62 -> '+'
    | 62uy ->  '+'
    // 63 -> '/'
    | 63uy ->  '+'
    | _ -> invalidArg "b" (b.ToString()) // "Value must be [0-63] "

let bytesToBase64Bytes (a:byte) (b:byte) (c:byte) : (byte list) =
    let b0 = (a &&& 0b11111100uy) >>> 2
    let b1 = ((a &&& 0b00000011uy) <<< 4) ||| ((b &&& 0b11110000uy) >>> 4)
    let b2 = ((b &&& 0b00001111uy) <<< 2) ||| ((c &&& 0b11000000uy) >>> 6)
    let b3 = c &&& 0b00111111uy
    [b0;b1;b2;b3]

let rec byteListToBase64 (bs:byte list) : (char list) =
    match bs with
    | []-> []
    | x::y::z::zs-> ((bytesToBase64Bytes x y z) |> List.map byteToBase64) @ (byteListToBase64 zs)
    | x::y::ys -> ((bytesToBase64Bytes x y 0uy) |> List.map byteToBase64 |> Seq.take 3 |> Seq.toList) @ ['=']
    | x::xs -> ((bytesToBase64Bytes x 0uy 0uy) |> List.map byteToBase64 |> Seq.take 2 |> Seq.toList) @ ['=';'=']

let hexToBase64 (hex:string) : (string) =
    hex |> hexDecode |> byteListToBase64 |> System.String.Concat

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

// http://en.wikipedia.org/wiki/Hamming_distance
let hammingDistance (b0:byte) (b1:byte) =
    let rec hd (v:byte) (distance:byte) =
        match v with
        | 0uy -> distance
        | _ -> hd (v &&& (v - 1uy)) (distance + 1uy)
    let distance = hd (b0 ^^^ b1) 0uy
    distance

let hammingDistanceBytes (bytes0:byte seq) (bytes1:byte seq) : (int) =
    Seq.zip bytes0 bytes1
    |> Seq.map (fun (b0,b1) -> hammingDistance b0 b1)
    |> Seq.sumBy (fun x -> int(x))

let hammingDistanceText (text0:string) (text1:string) : (int) =
    Array.zip (text0.ToCharArray()) (text1.ToCharArray())
    |> Array.map (fun (b0,b1) -> hammingDistance (byte(b0)) (byte(b1)))
    |> Array.sumBy (fun x -> int(x))

let nths (arrays:'a [] []) (n:int) : ('a []) =
    arrays |> Array.choose (fun array -> if (n < array.Length) then Some (Array.get array n) else None)

let transpose (xss:'a [] []) : ('a [] []) =
    let length = xss.[0].GetLength(0)
    let lengths = [|0 .. length - 1|]
    lengths |> Array.map (fun n -> nths xss n)

let xorDecrypt (key:byte) (bytes:byte seq) : (byte seq) =
    bytes |> Seq.map (fun b -> key ^^^ b)

let xorDecrypt2 (keyArray:byte []) (bytes:byte seq) : (byte seq) =
    let keyLength =  keyArray.Length
    bytes |> Seq.mapi (fun i b ->
        let k = keyArray.[i % keyLength]
        (k ^^^ b))

let scoreText (text:string) : (int) =
    text.ToLower().ToCharArray() |> Array.sumBy (fun c ->
        match c with
        | 'a' -> 81
        | 'b' -> 14
        | 'c' -> 27
        | 'd' -> 42
        | 'e' -> 127
        | 'f' -> 22
        | 'g' -> 20
        | 'h' -> 60
        | 'i' -> 69
        | 'j' -> 2
        | 'k' -> 7
        | 'l' -> 40
        | 'm' -> 24
        | 'n' -> 67
        | 'o' -> 75
        | 'p' -> 19
        | 'q' -> 1
        | 'r' -> 59
        | 's' -> 63
        | 't' -> 91
        | 'u' -> 28
        | 'v' -> 10
        | 'w' -> 23
        | 'x' -> 2
        | 'y' -> 20
        | 'z' -> 1
        | '\r' -> 10
        | '\n' -> 10
        | '.' -> 10
        | ',' -> 10
        | '?' -> 10
        | ',' -> 10
        | ' ' -> 10
        | x when byte(x) > 126uy -> -1000
        | x when byte(x) < 32uy -> -100
        | _ -> 0)

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

let toText2 (chars:char seq) : (string) =
    chars |> String.Concat

let escapeChars (chars:char seq) : (char seq) =
    chars |> Seq.map (fun c ->
        match c with
        | x when x >= ' ' && x <= '~' -> x
        | _ -> '?')

let escapeText (text:string) : (string) =
    text.ToCharArray() |> escapeChars |> String.Concat

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

let breakCode (bytes:byte []) =
    let keySizes = [2 .. 40]
    let distances =
        keySizes
        |> List.map (fun keySize -> 
            let blocks = chunk keySize bytes |> Seq.map (fun b -> b |> Seq.toArray) |> Seq.filter (fun x -> x.Length = keySize) |> Seq.toArray
            let averageDistance = blocks |> Seq.windowed 2 |> Seq.map (fun arr -> float(hammingDistanceBytes arr.[0] arr.[1])) |> Seq.take 4 |> Seq.average
            let normalizedDistance =  float(averageDistance) / float(keySize)
            (keySize, normalizedDistance))
        |> List.sortBy (fun (_,d) -> d)
        |> Seq.take 5
        |> Seq.toList
    let keys = [|0uy .. 127uy|]
    let decryptors = keys |> Array.map (fun keyByte -> (keyByte, xorDecrypt keyByte))
    
    let decryptedTexts = distances |> List.map (fun (keySize,_) -> 
        let blocks = bytes |> chunk keySize |> Seq.toArray
        let transposedBlocks = transpose blocks

        let bestDecryptedBlocks = transposedBlocks |> Array.map (fun block ->
            let decryptedScores =
                decryptors |> Array.map (fun (keyByte, decryptor) ->
                    let decryptedBytes = decryptor block |> Seq.toArray
                    let decryptedText = toText decryptedBytes
                    let score = scoreText decryptedText
                    (keyByte, score, decryptedText |> escapeText))
                |> Array.sortBy (fun (_,s,_) -> -s)
            decryptedScores.[0])

        let decryptedText =
            let keyBytes = bestDecryptedBlocks |> Array.map (fun (keyByte, _, _)  -> keyByte)
            let plainText = xorDecrypt2 keyBytes bytes |> toText
            let keyText = keyBytes |> toText
            (keyText, plainText)
        decryptedText)
    decryptedTexts |> List.sortBy (fun (key,text) -> -(scoreText text)) |> List.head

let path = @"C:\Users\ryanj\Documents\GitHub\cryptopals\matasano\6.txt"
let doit path =
    let lines = System.IO.File.ReadAllLines path
    let text = lines |> Array.fold (fun s text -> String.Concat [|s;text|]) ""
    let bytes = base64Decode text |> List.toArray
    breakCode bytes
