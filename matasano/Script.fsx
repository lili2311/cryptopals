// Learn more about F# at http://fsharp.net. See the 'F# Tutorial' project
// for more guidance on F# programming.

//#load "Library1.fs"
//#r @"C:\Users\Crystal\Documents\GitHub\cryptopals\matasano\packages\FSharpx.Collections.1.9.4\lib\net35\FSharpx.Collections.dll"

//open matasano
//open FSharpx.Collections

// Define your library scripting code here

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

let byteToHex (b:byte) : (string) = b.ToString("X2")
let hexEncode (bs:byte list) : (string) =
    bs |> List.map byteToHex |> System.String.Concat

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

// S1C1
let hexToBase64 (hex:string) : (string) =
    hex |> hexDecode |> byteListToBase64 |> System.String.Concat

// S1C2
let fixedXor (s0:string) (s1:string) =
    let bs0 = s0.ToCharArray() |> Array.toList |> hexToBytes 
    let bs1 = s1.ToCharArray() |> Array.toList |> hexToBytes
    List.zip bs0 bs1 |> (List.map (fun (a,b) -> a ^^^ b)) |> hexEncode