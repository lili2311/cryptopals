open System
open System.IO
open System.Security.Cryptography

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

let detectAesEcb (bytes:byte seq) : (bool) =
    // block size is always 16 bytes for AES
    let blockSize = 16
    let blocks = chunk blockSize bytes
    let setBlocks = blocks |> Set.ofSeq
    blocks |> Seq.length = (setBlocks |> Set.count)


let path = @"C:\Users\ryanj\Documents\GitHub\cryptopals\matasano\8.txt"
let doit path =
    let lines = System.IO.File.ReadAllLines path
    let linesBytes = lines |> Array.map (fun s -> hexDecode s |> List.toArray)
    linesBytes |> Array.find (detectAesEcb)
