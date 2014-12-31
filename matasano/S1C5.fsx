//Implement repeating-key XOR
//
//Here is the opening stanza of an important work of the English language: 
//Burning 'em, if you ain't quick and nimble
//I go crazy when I hear a cymbal
//
//Encrypt it, under the key "ICE", using repeating-key XOR. 
//
//In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on. 
//
//It should come out to: 
//0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
//
//Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this. 

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

let hexEncode (b:byte) : (string) = b.ToString("X2")

let xorEncrypt (text:string) (key:string) : (string) =
    let keyChars = Seq.initInfinite (fun n -> key.Chars (n % key.Length))
    let textChars = text.ToCharArray()
    let cipherBytes = Seq.zip keyChars textChars |> Seq.map (fun (a,b) -> byte(a) ^^^ byte(b))
    let hexEncodedCipherChars = cipherBytes |> Seq.collect hexEncode
    let encodedText = new String(hexEncodedCipherChars |> Seq.toArray)
    encodedText

let answer = xorEncrypt "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" "ICE"
let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".ToUpper()
