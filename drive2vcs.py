#!/usr/bin/python

from requests_oauthlib import OAuth2Session
import subprocess
import platform
import os
from dateutil import parser
from dateutil import tz
import json
import argparse

"""
https://docs.google.com/document/export?id=C-c-censored!&revision=???&exportFormat=zip
https://docs.google.com/document/export?id=C-c-censored!&revision=???&exportFormat=odt
https://docs.google.com/spreadsheets/export?id=C-c-censored!&revision=196&exportFormat=ods
https://docs.google.com/presentation/export?id=C-c-censored!&revision=???&exportFormat=odp
https://docs.google.com/drawings/export?id=C-c-censored!&revision=???&exportFormat=svg

blah = {'application/vnd.oasis.opendocument.text':'odt',
	'text/plain':'txt',
	'application/vnd.openxmlformats-officedocument.wordprocessingml.document':'docx',
	'application/rtf':'rtf',
	'text/html':'html+zip',
	'application/pdf':'pdf'}
"""
lopath=None
if platform.system() == 'Windows':
	import winreg
	try:
		loffice=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\LibreOffice\\LibreOffice")
		lopath=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\LibreOffice\\LibreOffice\\{}".format(winreg.EnumKey(loffice, 0)))
		lopath=winreg.QueryValueEx(lopath, 'Path')[0]
	except OSError as e:
		print("Libreoffice isn't installed, so...we can't do *.od* -> *.fod* conversion to make things easier on git...")
else:
	retcode=subprocess.call(['which','libreoffice'])
	if retcode == 0:
		lopath='libreoffice'
	else:
		print("Libreoffice isn't installed, so...we can't do *.od* -> *.fod* conversion to make things easier on git...")

if __name__ == "__main__":
	aparser = argparse.ArgumentParser(prog='drive2vcs', description="Make git repos for each file on google drive")
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

	export_format = {
		'application/vnd.google-apps.document':('document','odt'),
		'application/vnd.google-apps.spreadsheet':('spreadsheets','ods'),
		'application/vnd.google-apps.presentation':('presentation','odp'),
		'application/vnd.google-apps.drawing':('drawings','svg')
		}
	export_format['application/vnd.google-apps.kix'] = export_format['application/vnd.google-apps.document']
	export_format['application/vnd.google-apps.ritz'] = export_format['application/vnd.google-apps.spreadsheet']
	export_format['application/vnd.google-apps.punch'] = export_format['application/vnd.google-apps.presentation']
	export_url_tpl="https://docs.google.com/{}/export?id={}&revision={}&exportFormat={}"

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

	#unoconv --stdout -f fodt
	#libreoffice --headless --convert-to fodt --outdir /tmp /tmp/BoundSequelIdea.odt <- for storage AND git logs
	#libreoffice --headless --convert-to txt:Text --outdir /tmp /tmp/BoundSequelIdea.odt <- for git logs?

	#find /dir -type f -inum <inode value> -mount
	#http://superuser.com/questions/81563/whats-a-good-solution-for-file-tagging-in-linux

	for gdrive_id in args.fids:
		max_rev = oauth.get(api_url_tpl.format("/files/{}/revisions/head".format(gdrive_id))).json()
		f_repo_path = os.path.join(args.directory,gdrive_id)
		f = oauth.get(api_url_tpl.format("/files/{}".format(gdrive_id))).json()
		title = f['title'].replace('/', ' or ')
		
		desc_fname = os.path.join(f_repo_path,".desc")
		
		if f['mimeType'] in export_format.keys():
			fname = os.path.join(f_repo_path,"{}.{}".format(title,export_format[f['mimeType']][1]))
			ffname = os.path.join(f_repo_path,"{}.f{}".format(title,export_format[f['mimeType']][1]))
		elif f['mimeType'] == 'application/vnd.google-apps.folder':
			continue
		else:
			fname = os.path.join(f_repo_path,"{}.{}".format(title,export_format[f['mimeType']][1]))

		print("{} - {} ({})".format(gdrive_id, title, f['mimeType']))
		if not os.path.exists(f_repo_path):
			os.makedirs(f_repo_path)
			subprocess.call(['git', 'init'], cwd=f_repo_path)
		for rid in range(1,int(max_rev['id'])+1):
			rev=oauth.get(api_url_tpl.format("/files/{}/revisions/{}".format(gdrive_id, rid)))
			if rev.status_code == 404:
				print("Revision {} doesn't exist, continuing...".format(rid))
				continue
			else:
				rev=rev.json()
			rev_chk=''
			try:
				rev_chk=subprocess.check_output(['git', 'log', '--grep', 
							'Revision {} @'.format(rev['id'])], 
							cwd=f_repo_path)
			except subprocess.CalledProcessError:
				pass
			else:
				if rev_chk != b'':
					print("We already have revision {}, continuing...".format(rev['id']))
					continue
			if rev.get('downloadUrl') is None:
				gdoc_indicator="[GDOC] Revision {} @ {}"
				optfmt=export_format[f['mimeType']]
				exportUrl=export_url_tpl.format(optfmt[0],gdrive_id,rev['id'],optfmt[1])
				#print(exportUrl)
				data=oauth.get(exportUrl)
			else:
				gdoc_indicator="[FILE] Revision  {} @ {}"
				data=oauth.get(rev.get('downloadUrl'))
			
			#"""
			with open(fname, 'wb') as fd:
				for chunk in data.iter_content(1024):
					fd.write(chunk)
				#print(fname)
			if f['mimeType'] in export_format.keys() and export_format[f['mimeType']][1][0] == "o" and lopath is not None:
				subprocess.call([lopath, '--headless', '--convert-to', 
					'f{}'.format(export_format[f['mimeType']][1]), os.path.abspath(fname)], cwd=f_repo_path)
				subprocess.call(['git', 'add', ffname], cwd=f_repo_path)
			else:
				subprocess.call(['git', 'add', fname], cwd=f_repo_path)
			revdate=parser.parse(rev['modifiedDate']).astimezone(tz.tzlocal())
			gdoc_indicator = gdoc_indicator.format(rev['id'], revdate)
			os.environ['GIT_COMMITTER_DATE']=revdate.isoformat()
			subprocess.call(['git', 'commit', '--date', revdate.isoformat(), 
					'-m', gdoc_indicator], cwd=f_repo_path)
			#"""
		else:
			if f['mimeType'] in export_format.keys() and export_format[f['mimeType']][1][0] == "o" and lopath is not None:
				if os.path.exists(fname):
					os.remove(fname)
			if 'description' in f.keys():
				with open(desc_fname, 'w', encoding='utf-8') as descfd:
					descfd.write(f['description'])
