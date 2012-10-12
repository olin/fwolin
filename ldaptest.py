import ldap, base64

def test(secret):
	server = "ldap://ldap.olin.edu"
	dn = "MILKYWAY"
	username = "tryan"

	try:
		dn = dn + "\\" + username

		ldap.set_option(ldap.OPT_REFERRALS, 0)
		l = ldap.initialize(server)
		l.protocol_version = 3
		l.simple_bind_s(dn, secret)

		## The next lines will also need to be changed to support your search requirements and directory
		baseDN = "dc=olin,dc=edu"
		searchScope = ldap.SCOPE_SUBTREE
		## retrieve all attributes - again adjust to your needs - see documentation for more options
		retrieveAttributes = None 
		searchFilter = "sAMAccountName=%s" % username

		ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
		result_set = []
		while 1:
			result_type, result_data = l.result(ldap_result_id, 0)
			if (result_data == []):
				break
			else:
				## here you don't have to append to a list
				## you could do whatever you want with the individual entry
				## The appending to list is just for illustration. 
				if result_type == ldap.RES_SEARCH_ENTRY:
					return result_data[0][1]['mail'][0]

	except ldap.INVALID_CREDENTIALS, e:
		print e
		return False