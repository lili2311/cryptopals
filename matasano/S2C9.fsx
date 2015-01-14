
let pkcs7 (blockSize:byte) (bytes:byte []) =
    let extra = bytes.Length % int(blockSize)
    if (extra = 0)
    then bytes
    else
        let paddingCount = int(blockSize) - extra
        let paddingByte = byte(paddingCount)
        (bytes |> Array.toList) @ (List.replicate paddingCount paddingByte) |> List.toArray

let doit =
    let blockSize = 20uy
    pkcs7 blockSize ("YELLOW SUBMARINE".ToCharArray() |> Array.map (fun c -> byte(c)))