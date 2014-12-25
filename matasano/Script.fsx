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
    let bs0 = s0 |> hexDecode
    let bs1 = s1 |> hexDecode
    List.zip bs0 bs1 |> (List.map (fun (a,b) -> a ^^^ b)) |> hexEncode

// S1C3
let fixedXor2 (bs0:byte list) (bs1:byte list) : (byte list) =
    List.zip bs0 bs1 |> (List.map (fun (a,b) -> a ^^^ b))

let decodeHexEncodedSingleByteXorCipher (c:char) (s:string) =
    let bytes = hexDecode s
    let b = (byte)c
    let source = List.init (bytes.Length) (fun _ -> b)
    let xored = fixedXor2 source bytes
    let chars = xored |> List.map (fun x -> (char)x)
    chars |> System.String.Concat
    
let getDist (s:string) =
    let total = s.Length
    let letters = ['a' .. 'z']
    let frequency = letters |> List.map (fun x -> (x,  s.ToLower().ToCharArray() |> Array.toList |> List.filter (fun z -> z.Equals(x)) |> List.length))
    let dist = frequency |> List.map (fun (c,f) -> (c, (float)f / (float)total)) |> Map.ofList
    dist

let score (s:string) =
    let normals = [
        ('a',0.08167)
        ('b',0.01492)
        ('c',0.02782)
        ('d',0.04253)
        ('e',0.12702)
        ('f',0.02228)
        ('g',0.02015)
        ('h',0.06094)
        ('i',0.06966)
        ('j',0.00153)
        ('k',0.00772)
        ('l',0.04025)
        ('m',0.02406)
        ('n',0.06749)
        ('o',0.07507)
        ('p',0.01929)
        ('q',0.00095)
        ('r',0.05987)
        ('s',0.06327)
        ('t',0.09056)
        ('u',0.02360)
        ('v',0.00978)
        ('w',0.02360)
        ('x',0.00150)
        ('y',0.01974)
        ('z',0.00074)] |> Map.ofList
    let dist = getDist s
    let theScore =
        dist |>
        Map.toList |>
        List.map (fun (k,v) ->
            normals.TryFind k |>
            (fun o -> if Option.isSome o then o else Some 0.0) |>
            Option.get |>
            (-) v |>
            (fun x -> x * x)) |>
        List.sum
    theScore

let getScores (text:string) =
    ['a' .. 'z'] @ ['A' .. 'Z'] |>
    List.map (fun c -> decodeHexEncodedSingleByteXorCipher c text) |>
    List.map (fun s -> (score s, s)) |>
    List.sortBy (fun (s,r) -> s);;

let theText = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";