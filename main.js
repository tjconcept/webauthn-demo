import join from 'https://esm.sh/psjoin@2.0.1'
import {equals} from 'https://esm.sh/jsr/@std/bytes@1.0.2/equals.js'
import {
	pubKeyCredParams,
	creationOptionsToJSON,
	requestOptionsToJSON,
	parseCreationOptionsFromJSON,
	parseRequestOptionsFromJSON,
	assertionToJSON,
	assertionFromJSON,
	attestationToJSON,
	attestationFromJSON,
} from 'https://esm.sh/gh/tjconcept/webauthn-json@1.2.0'
import {
	importKey,
	verifySignature,
	getChallenge,
	parseAuthenticatorData,
} from 'https://esm.sh/gh/tjconcept/webauthn-tools@1.1.0'

// As this demo runs the *server part* in a browser too, the recommended -8
// algorithm is not used as it still lacks support in browsers. However, it is
// supported in recent Node.js and Deno. The client part does not require
// actual support for the algorithm as that lies within the authenticator
// device.
const supportedAlgorithms = new Set([-7, -257])

const store = localStorage
const $signIn = document.querySelector('#sign-in')
const $signUp = document.querySelector('#sign-up')
$signUp.addEventListener('click', () => {
	const credential = navigator.credentials.create({
		// https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
		publicKey: parseCreationOptionsFromJSON(
			JSON.parse(serverWebauthnCreate()),
		),
	})
	join(credential, (credential) => {
		console.log(
			'Signing up. Server payload:',
			attestationToJSON(credential),
		)
		return serverWebauthnStore(
			JSON.stringify(attestationToJSON(credential)),
		)
	})
})
$signIn.addEventListener('click', () => {
	const challenge = createRandom(16) // Note: fetch from a server
	const credential = navigator.credentials.get({
		// https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
		publicKey: parseRequestOptionsFromJSON(
			JSON.parse(serverWebauthnGet(challenge)),
		),
	})
	const verified = join(credential, (credential) =>
		serverWebauthnVerify(
			challenge,
			JSON.stringify(assertionToJSON(credential)),
		),
	)
	join(credential, verified, (credential, verified) => {
		console.log('Logging in. Server payload:', assertionToJSON(credential))
		console.log(verified ? 'Verified' : 'Verification failed')
	})
})

function serverWebauthnCreate() {
	const challenge = createRandom(16)
	const userId = createRandom(16)
	return JSON.stringify(
		creationOptionsToJSON({
			// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
			authenticatorSelection: {
				residentKey: 'required', // allow user-agent to show a list
			},
			challenge,
			pubKeyCredParams: pubKeyCredParams.filter((p) =>
				supportedAlgorithms.has(p.alg),
			),
			rp: {
				name: 'Demo entity',
			},
			user: {
				id: userId,
				name: `demo-${userId.toHex().slice(-8)}`,
				displayName: `demo-${userId.toHex().slice(-8)}`,
			},
		}),
	)
}

function serverWebauthnStore(data) {
	const credential = attestationFromJSON(JSON.parse(data))
	if (!supportedAlgorithms.has(credential.response.publicKeyAlgorithm)) {
		throw new Error(
			`Unsupported key algorithm. Got "${credential.response.publicKeyAlgorithm}"`,
		)
	}

	console.log(
		'Parsed authenticator data',
		parseAuthenticatorData(credential.response.authenticatorData),
	)
	store.setItem(credential.id, JSON.stringify(attestationToJSON(credential)))
}

function serverWebauthnGet(challenge) {
	return JSON.stringify(
		requestOptionsToJSON({
			// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
			challenge, // Note: generate and store on a server
		}),
	)
}

function serverWebauthnVerify(challenge, data) {
	const credential = assertionFromJSON(JSON.parse(data))
	const signatureChallenge = getChallenge(credential.response.clientDataJSON)
	if (!equals(signatureChallenge, challenge)) {
		throw new Error(
			`Bad challenge. Expected "${challenge}" got "${signatureChallenge}"`,
		)
	}

	const attestation = attestationFromJSON(
		JSON.parse(store.getItem(credential.id)),
	)
	if (!attestation) {
		throw new Error(`Credential unknown: ${credential.id}`)
	}

	const key = importKey({
		algorithm: attestation.response.publicKeyAlgorithm,
		data: attestation.response.publicKey,
	})
	const verified = join(key, (key) =>
		verifySignature({
			key,
			authenticatorData: credential.response.authenticatorData,
			clientDataJSON: credential.response.clientDataJSON,
			signature: credential.response.signature,
		}),
	)
	console.log(
		'Parsed authenticator data',
		parseAuthenticatorData(credential.response.authenticatorData),
	)
	return verified
}

function createRandom(bytes) {
	const d = new Uint8Array(bytes)
	crypto.getRandomValues(d)
	return d
}
