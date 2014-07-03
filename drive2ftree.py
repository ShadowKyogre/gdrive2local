#!/usr/bin/python

from requests_oauthlib import OAuth2Session
import subprocess
import os
from dateutil import parser
from dateutil import tz
import json
import argparse

if __name__ == "__main__":
	aparser = argparse.ArgumentParser(prog='drive2ftree', description="Makes a directory tree from the given folder ids")
	aparser.add_argument('fids', metavar='N', type=str, nargs='*',
						help='file IDs to process')
	aparser.add_argument('-d','--directory', help='Save the file in this directory', default=".")
	aparser.add_argument('-c','--client-auth', 
					 help='Alternate file for client authentication',
					 default=os.path.expanduser("~/.config/drive2vcs/client.json"))
	aparser.add_argument('-t','--token', 
					 help='Alternate file for token storage',
					 default=os.path.expanduser("~/.config/drive2vcs/token.json"))
	args = aparser.parse_args(os.sys.argv[1:])

	token_storage = args.token
	client_stuff = args.client_auth

	os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

	with open(client_stuff) as f:
		cstuff = json.load(f)
		client_id = cstuff['client_id']
		client_secret = cstuff['client_secret']

	redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
	scope = ['https://www.googleapis.com/auth/drive.readonly']

	if os.path.exists(token_storage):
		with open(token_storage) as t:
			token = json.load(t)
	else:
		token = None

	def token_saver(token):
		with open(token_storage, 'w', encoding='utf-8') as t:
			t.write(json.dumps(token))

	oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, token=token,
						auto_refresh_url='https://accounts.google.com/o/oauth2/token',
						auto_refresh_kwargs=cstuff,
						token_updater=token_saver,
						scope=scope)

	if token is None:
		authorization_url, state = oauth.authorization_url(
				'https://accounts.google.com/o/oauth2/auth',
				# access_type and approval_prompt are Google specific extra
				# parameters.
				access_type="offline", approval_prompt="auto")

		print('Please go to {} and authorize access.'.format(authorization_url))
		authorization_response = input('Enter the auth response: ')
		token = oauth.fetch_token(
				'https://accounts.google.com/o/oauth2/token',
				code=authorization_response,
				# Google specific extra parameter used for client
				# authentication
				client_secret=client_secret)
		token_saver(token)

	api_url_tpl = "https://www.googleapis.com/drive/v2{}"
	onlyfs = {'q':'mimeType="application/vnd.google-apps.folder"'}
	
	def make_ftree(f, parents=[args.directory]):
		c_url = api_url_tpl.format("/files/{}/children".format(f['id']))
		children = oauth.get(c_url, params=onlyfs).json()
		tree_path=parents+[f['title']]
		desty=os.path.join(*tree_path)
		print("Making:", desty)
		if not os.path.exists(desty):
			os.makedirs(desty)
		for c in children['items']:
			nf = oauth.get(c['childLink']).json()
			make_ftree(nf,parents=tree_path)
		if 'description' in f.keys():
			desc_fname = os.path.join(desty,".desc")
			with open(desc_fname, 'w', encoding='utf-8') as descfd:
				descfd.write(f['description'])

	for gdrive_id in args.fids:
		url = api_url_tpl.format("/files/{}".format(gdrive_id))
		f = oauth.get(url).json()
		make_ftree(f)