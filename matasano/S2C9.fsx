
let pkcs7 (blockSize:byte) (bytes:byte []) : (byte []) =
    let paddingCount = int(blockSize) - (bytes.Length % int(blockSize))
    let paddingByte = byte(paddingCount)
    (bytes |> Array.toList) @ (List.replicate paddingCount paddingByte) |> List.toArray

let doit =
    let blockSize = 20uy
    pkcs7 blockSize ("YELLOW SUBMARINE".ToCharArray() |> Array.map (fun c -> byte(c)))