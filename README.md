# node-rsa-cryptography

# install dependencies
npm i 

# generate keys: 
npm run start gene
# get public key: 
npm run start publicKey

# encrypt data: 
npm run start encr <text>

# decrypt data: 
npm run start decr <encrypted>

# arca encrypt data: 
npm run start arca-encr <text>

# zip project
zip -r node-rsa-cryptography.zip . -x "*node_modules/*" "*node_modules" "*.git/*" "*.git"

# clean dis/ and keys/ foldeers
rm -rf dist/ keys/ node-rsa-cryptography.zip