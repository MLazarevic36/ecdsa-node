const express = require("express")
const app = express()
const cors = require("cors")
const port = 3042
const secp = require("ethereum-cryptography/secp256k1")
const { utf8ToBytes } = require("ethereum-cryptography/utils")
const { keccak256 } = require("ethereum-cryptography/keccak")
const { extractPublicKey } = require("./scripts/helper")

app.use(cors())
app.use(express.json())

const balances = {
	//private: 56c49d777b3273b4c70c38e0fd14e68f73bf0fa982ee275ced8fa5112e6ec4a7
	d45086b85911872bafff0d9ec48c42fcc4a1662b: 100,
	//private: bd354b3834420478d7b707544c41289f1f3e82fa52e11f9ca80cdf0fbd84205d
	a66ed6cfe76c18fd125ae18c200bea361062fb65: 50,
	//private: e5ae4a0f1f0f12c6b11fc877d283e7fe67f03613222cf4f415edd20a09c38079
	c21ef87ec33566248cedeb90e4519220c42df463: 75,
}
app.get("/balance/:address", (req, res) => {
	const { address } = req.params
	const balance = balances[address] || 0
	res.send({ balance })
})

function verifySignature(fullSignature, msg, pubKey) {
	const msgHash = keccak256(utf8ToBytes(msg))
	let signature = fullSignature.slice(0, fullSignature.length - 1)
	let recovery = parseInt(fullSignature[fullSignature.length - 1])
	const sigPubKey = secp.recoverPublicKey(msgHash, signature, recovery)
	const keyFromSig = extractPublicKey(sigPubKey)
	return keyFromSig == pubKey
}

app.post("/send", (req, res) => {
	//get a signature from client side
	//recover public address from the signature
	const { sender, recipient, amount, signature } = req.body

	setInitialBalance(sender)
	setInitialBalance(recipient)

	const message = `Transfer ${amount} from ${sender} to ${recipient}`

	let isValid = verifySignature(signature, message, sender)
	if (isValid === false) {
		return res.status(400).send({ message: "Invalid Signature!" })
	}

	if (balances[sender] < amount) {
		res.status(400).send({ message: "Not enough funds!" })
	} else {
		balances[sender] -= amount
		balances[recipient] += amount
		res.send({ balance: balances[sender] })
	}
})

app.listen(port, () => {
	console.log(`Listening on port ${port}!`)
})

function setInitialBalance(address) {
	if (!balances[address]) {
		balances[address] = 0
	}
}
