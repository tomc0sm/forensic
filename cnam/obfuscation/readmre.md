## Analyse obfsucation 

- date :06/01/2020

- files

  - `7F364A512306A5CBD0518AEC871D0A4D`

  - `9A0CCDDA5A8643F8069DA2FA2D438401`

  - `9A0CCDDA5A8643F8069DA2FA2D438401.key`

  - `49B1C8F19CEB9A776C2114557CF2D5C1`

  - `54E8914D704E4B564720BACF7C665F50`

  - `245E9C385087A35C29718A85CF742037`

  - `B4890BB1A8318357E5F8456C363BA647`

    

- `7F364A512306A5CBD0518AEC871D0A4D` 
  
  - xor `81965CCC` with expected `4d5a9000` (MZ Header PE Format)
  - file is xored with `CC` key 
  - decrypt file Hash `72556227c568b3f12d3a70cfb5e00792` 
  - hidden message in strings : "This is the INetSim default binary"
  
  
  
- `9A0CCDDA5A8643F8069DA2FA2D438401`

- `9A0CCDDA5A8643F8069DA2FA2D438401.key`

- the 2nd file contains decrypt parts like "Exif" or "GIMP" that are encrypted in the 1st file. can test xor 

  - exif  => `05786966` ^  `45786966` = `40000000`
  - GIMP => `47494D50` ^ `58F34350` = `1fba0e00`

- WRONG WAY

- the 2nd file contains  jpeg signature

  - `FFD8FF` ^ `B2826F` = `4d5a90` = PE Format signature

- 2nd file is really the key ! Let's try 

- decrypt file hash `295ab18e12ab9a7574f8194aee6c7200`

- hidden message in strings : "This is the INetSim default binary"

  

- `49B1C8F19CEB9A776C2114557CF2D5C1`

  - pattern found `337744627174384132367266414E7571` from the end of file with multiple rotations
    - rotation(1) key = key[1:] + key[0] all 80 octets / 5 lines of 16 octets
    - rotation(2) key = key[:dotIndex] + '0A' + key[dotIndex:]  all 80 octets / 5 lines of 16 octets
      - dotIndex += 6  
    - rotation(3) = rotation(1) all 24 lines / 384 octets / 24 lines of 16 octets

  

- `54E8914D704E4B564720BACF7C665F50`

  - peformat. : always the same file 

  - same code twice. wtf ? 

  - PADDINGXX at the end : maybe garbage to bypass AV signatures db

    

- `245E9C385087A35C29718A85CF742037`

  - start with a jpeg / gimp signature :  black image " This is the inetSim default image"
  - the inetSim default binary is hidden into the image  
