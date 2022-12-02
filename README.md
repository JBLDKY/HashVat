## HashVat
### A blazingly fast and memory safe password cracker with user interface.

HashVat runs with user interface and is capable of cracking the 1.000.000 most common passwords that are hashed with sha1 or sha256.

Enter a sha1 or sha256 in their respective input fields and hit crack to crack.
Enter a password in the Cleartext field and select either algorithm to get the hash. This also adds the password to the list of known passwords.
![image](https://user-images.githubusercontent.com/87128575/205406834-54f17951-a248-4384-a2a0-60775786ae3e.png)

### Instructions
1. Clone the repository
2. Open a terminal and navigate to the newly created directory
3. execute the following command: "cargo run" 

Alternatively execute the "cargo build --release" command to create an executable.

Inspired by HashCat:
https://hashcat.net/hashcat/
