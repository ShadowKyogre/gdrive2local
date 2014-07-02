from requests_oauthlib import OAuth2Session
import os

"""
https://docs.google.com/document/export?id=CENSORED&revision=???&exportFormat=zip
https://docs.google.com/document/export?id=CENSORED&revision=???&exportFormat=odt
https://docs.google.com/spreadsheets/export?id=CENSORED&revision=196&exportFormat=ods
https://docs.google.com/presentation/export?id=CENSORED&revision=???&exportFormat=odp
https://docs.google.com/drawings/export?id=CENSORED&revision=???&exportFormat=svg

blah = {'application/vnd.oasis.opendocument.text':'odt',
	'text/plain':'txt',
	'application/vnd.openxmlformats-officedocument.wordprocessingml.document':'docx',
	'application/rtf':'rtf',
	'text/html':'html+zip',
	'application/pdf':'pdf'}
"""

export_format = {'application/vnd.google-apps.document':('document','odt'),
				'application/vnd.google-apps.spreadsheet':('spreadsheets','ods'),
				'application/vnd.google-apps.presentation':('presentation','odp'),
				'application/vnd.google-apps.drawing':('drawings','svg')}
export_format['application/vnd.google-apps.kix'] = export_format['application/vnd.google-apps.document']
export_format['application/vnd.google-apps.ritz'] = export_format['application/vnd.google-apps.spreadsheet']
export_format['application/vnd.google-apps.punch'] = export_format['application/vnd.google-apps.presentation']
export_url_tpl="https://docs.google.com/{}/?id={}&revision={}&exportFormat={}"


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

client_id = r'PUTINYOUROWN'
client_secret = r'PUTINYOUROWN'
redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
scope = ['https://www.googleapis.com/auth/drive.readonly']

oauth = OAuth2Session(client_id, redirect_uri=redirect_uri,
					scope=scope)

authorization_url, state = oauth.authorization_url(
			'https://accounts.google.com/o/oauth2/auth',
			# access_type and approval_prompt are Google specific extra
			# parameters.
			access_type="offline", approval_prompt="force")

print('Please go to {} and authorize access.'.format(authorization_url))
authorization_response = input('Enter the auth response: ')
token = oauth.fetch_token(
			'https://accounts.google.com/o/oauth2/token',
			code=authorization_response,
			# Google specific extra parameter used for client
			# authentication
			client_secret=client_secret)

api_url_tpl = "https://www.googleapis.com/drive/v2{}"

for gdrive_id in os.sys.argv[1:]:
	r = oauth.get(api_url_tpl.format("/files/{}/revisions".format(gdrive_id)))
	f_repo_path = '/tmp/gdrive/{}'.format(gdrive_id)
	f = oauth.get(api_url_tpl.format("/files/{}".format(gdrive_id))).json()
	title = f['title']
	
	if f['mimeType'] in export_format:
		fname = os.path.join(f_repo_path,"{}.{}".format(title,export_format[f['mimeType']][1]))
	else:
		fname = os.path.join(f_repo_path,"{}.{}".format(title,export_format[f['mimeType']][1]))
	
	print("{} - {} ({})".format(gdrive_id, title, f['mimeType']))
	if not os.path.exists(f_repo_path):
		os.makedirs(f_repo_path)
	for rev in r.json()['items']:
		if rev.get('downloadUrl') is None:
			gdoc_indicator="[GDOC] {} @ {}"
			#optfmt=export_format[f['mimeType']]
			#exportUrl=export_url_tpl.format(optfmt[0],gdrive_id,rev['id'],optfmt[1])
			#data=oauth.get(rev.get(exportUrl))
		else:
			gdoc_indicator="[FILE] {} @ {}"
			#data=oauth.get(rev.get('downloadUrl'))
		print(gdoc_indicator.format(rev['id'], rev['modifiedDate']))
		
		"""
		with open(filename, 'wb') as fd:
			for chunk in data.iter_content(chunk_size):
				fd.write(chunk)
		"""