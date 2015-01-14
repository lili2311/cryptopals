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

let toByte (char:char) : (byte) =
    byte(char)
let toBytes (chars:char seq) : (byte seq) =
    chars |> Seq.map toByte

let decrypt (keyBytes:byte []) (iv:byte []) (bytes:byte []) =
    let aes = Aes.Create()
    aes.BlockSize <- iv.Length * 8
    aes.Mode <- CipherMode.ECB
    aes.Key <- keyBytes
    aes.IV <- iv
    aes.Padding <- PaddingMode.None
    use stream = new MemoryStream(bytes)
    use decryptor = aes.CreateDecryptor()
    use cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read)
    use streamReader = new StreamReader(cryptoStream)
    streamReader.ReadToEnd()

let path = @"C:\Users\ryanj\Documents\GitHub\cryptopals\matasano\7.txt"
let doit path =
    let keyText = "YELLOW SUBMARINE"
    let keyBytes = keyText |> toBytes |> Seq.toArray

    let lines = System.IO.File.ReadAllLines path
    let text = lines |> Array.fold (fun s text -> String.Concat [|s;text|]) ""
    let bytes = base64Decode text |> List.toArray
    let iv = Array.zeroCreate 16
    
    decrypt keyBytes iv bytes
