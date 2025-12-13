from flask import *
import os
from fido2.server import *
from fido2.webauthn import *
import base64

app=Flask(__name__)

app.secret_key=os.urandom(32)

import base64
import json

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


@app.route('/register/begin')
def register_begin():
	rp = PublicKeyCredentialRpEntity(name="PageX", id="adityamitra5102.github.io")
	server = Fido2Server(rp)
	
	user='Aditya'
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
	return redirect(f'https://adityamitra5102.github.io/VerifiablePasskey/pagex.html?challenge={chalb64}&type=create&user_id={user}&callback=http://localhost:5000/register/complete')

@app.route('/register/complete')
def register_complete():
	state=session['state']
	
	clientDataJson=base64.urlsafe_b64decode(request.args.get('clientDataJSON'))
	attestationObject=base64.urlsafe_b64decode(request.args.get('attestationObject'))
	authenticatorId=base64.urlsafe_b64decode(request.args.get('authenticatorId'))

	rawId=authenticatorId
	
	respjsonxx={'clientDataJSON': clientDataJson, 'attestationObject': attestationObject}
	print(respjsonxx)
	
	resp=AuthenticatorAttestationResponse.from_dict(respjsonxx)
	
	cred={'rawId': rawId, 'response': resp}
	
	
	rp = PublicKeyCredentialRpEntity(name="PageX", id="adityamitra5102.github.io")
	server = Fido2Server(rp)

	auth_data=server.register_complete(state, cred)
	print(auth_data)
	cred=auth_data.credential_data
    
	cred_dict={'aaguid': cred.aaguid, 'credential_id': cred.credential_id, 'public_key': cred.public_key}

	scred=serialize_cred(cred_dict)
	return jsonify(json.loads(scred))
	
app.run(host='0.0.0.0', port=5000)