pagex='https://adityamitra5102.github.io/VerifiablePasskey/pagex.html'
myurl='http://localhost:5000'

from jose import jws
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import json
import io
from flask import *
import os
from fido2.server import *
from fido2.webauthn import *
import base64
from urllib.parse import urlparse

app=Flask(__name__)

app.secret_key=os.urandom(32)

private_key=None

try:
	with open('private_key.der', 'rb') as f:
		priv_der=f.read()
		private_key=serialization.load_der_private_key(priv_der, password=None)
except:
	private_key=None
	
if private_key is None:
	# Generate ECDSA key pair (in production, securely store the private key)
	private_key = ec.generate_private_key(ec.SECP256R1())
	# Serialize private key to DER format
	private_der = private_key.private_bytes( encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
	with open('private_key.der', 'wb') as f:
		f.write(private_der)

pagex_domain=urlparse(pagex).netloc

public_key = private_key.public_key()

# Serialize public key to JWK format for DID Document
public_numbers = public_key.public_numbers()
x = base64.urlsafe_b64encode(public_numbers.x.to_bytes(32, 'big')).decode('utf-8').rstrip('=')
y = base64.urlsafe_b64encode(public_numbers.y.to_bytes(32, 'big')).decode('utf-8').rstrip('=')
public_key_jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": x,
    "y": y
}

# Issuer DID
ISSUER_DID = "did:web:AdityaMitra5102.github.io/VPass-Issuer"

# Serve DID Document at /.well-known/did.json
@app.route('/.well-known/did.json', methods=['GET'])
def did_document():
    did_doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": ISSUER_DID,
        "verificationMethod": [
            {
                "id": f"{ISSUER_DID}#key-1",
                "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": ISSUER_DID,
                "publicKeyJwk": public_key_jwk
            }
        ],
        "authentication": [f"{ISSUER_DID}#key-1"],
        "assertionMethod": [f"{ISSUER_DID}#key-1"]
    }
    return jsonify(did_doc)

def serialize_cred(cred):
	cred2={'aaguid': base64.b64encode(cred['aaguid']).decode(), 'credential_id': base64.b64encode(cred['credential_id']).decode()}
	pubkey={}
	for x in cred['public_key']:
		if isinstance(cred['public_key'][x], bytes):
			pubkey[x]='base64_'+base64.b64encode(cred['public_key'][x]).decode()
		else:
			pubkey[x]=cred['public_key'][x]
	cred2['public_key']=pubkey
	return json.dumps(cred2)
    
def deserialize_cred(credjson):
	cred=json.loads(credjson)
	cred['aaguid']=base64.b64decode(cred['aaguid'])
	cred['credential_id']=base64.b64decode(cred['credential_id'])
	cred2={}

	for x in cred['public_key']:
		if not isinstance(cred['public_key'][x], int) and cred['public_key'][x].startswith('base64_'):
			cred2[int(x)]=base64.b64decode(cred['public_key'][x][len('base64_'):])
		else:
			cred2[int(x)]=cred['public_key'][x]
	return AttestedCredentialData.create(aaguid=cred['aaguid'], credential_id=cred['credential_id'], public_key=cred2)


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/register/begin', methods=['POST'])
def register_begin():
	userinfo=dict(request.form)
	rp = PublicKeyCredentialRpEntity(name="PageX", id=pagex_domain)
	server = Fido2Server(rp)
	
	user=userinfo['name']
	options, state = server.register_begin(
		PublicKeyCredentialUserEntity(
			id=user.encode(),
			name=user,
			display_name=user,
		),
	)
	
	print(options.public_key.challenge)

	chalb64=base64.urlsafe_b64encode(options.public_key.challenge).decode()
	session['state']=state
	session['user']=userinfo
	return redirect(f'{pagex}?challenge={chalb64}&type=create&user_id={user}&callback={myurl}/register/complete')




@app.route('/register/complete')
def register_complete():
	state=session['state']
	userinfo=session['user']
	clientDataJson=base64.urlsafe_b64decode(request.args.get('clientDataJSON'))
	attestationObject=base64.urlsafe_b64decode(request.args.get('attestationObject'))
	authenticatorId=base64.urlsafe_b64decode(request.args.get('authenticatorId'))

	rawId=authenticatorId
	
	respjsonxx={'clientDataJSON': clientDataJson, 'attestationObject': attestationObject}
	print(respjsonxx)
	
	resp=AuthenticatorAttestationResponse.from_dict(respjsonxx)
	
	cred={'rawId': rawId, 'response': resp}
	
	
	rp = PublicKeyCredentialRpEntity(name="PageX", id=pagex_domain)
	server = Fido2Server(rp)

	auth_data=server.register_complete(state, cred)
	print(auth_data)
	cred=auth_data.credential_data
    
	cred_dict={'aaguid': cred.aaguid, 'credential_id': cred.credential_id, 'public_key': cred.public_key}

	scred=serialize_cred(cred_dict)
	

    # Define the Verifiable Credential
	credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "http://example.org/credentials/3732",
        "type": ["VerifiableCredential", "VerifiablePasskey"],
        "issuer": ISSUER_DID,
        "issuanceDate": datetime.utcnow().isoformat(),
        "credentialSubject": {
            "id": "User creds",
            "user": userinfo,
            "pagex": pagex,
            "cred": json.loads(scred)
        }
    }

    # Sign the credential as JWS
	jws_token = jws.sign(credential, private_key, algorithm='ES256')

    # Create Verifiable Presentation
	presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "issuer": ISSUER_DID,
        "verifiableCredential": jws_token
	}

	session['vpass']=json.dumps(presentation)
	return render_template('success.html', user=userinfo['name'])

@app.route('/download')
def download():
	vpass=json.loads(session['vpass'])
	print(vpass)
	return send_file(io.BytesIO(json.dumps(vpass).encode()), mimetype='application/json', as_attachment=True, download_name='vpass.json')

if __name__ == '__main__':
	app.run(debug=True, port=5000)
    

    
