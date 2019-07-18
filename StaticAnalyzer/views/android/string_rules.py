RULES = [
	{
		'desc': 'Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.',
		'type': 'regex',
		'regex1': r'''(password\s*=\s*['|"].+['|"]\s{0,5})|(pass\s*=\s*['|"].+['|"]\s{0,5})|(username\s*=\s*['|"].+['|"]\s{0,5})|(secret\s*=\s*['|"].+['|"]\s{0,5})|(key\s*=\s*['|"].+['|"]\s{0,5})''',
		'level': 'high',
		'match': 'single_regex',
		'input_case': 'lower',
		'enable': 'false'
	},
	{
		'desc': 'IP Address disclosure',
		'type': 'regex',
		'regex1': r'((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))',
		'level': 'warning',
		'match': 'single_regex',
		'input_case': 'exact',
		'enable': 'false'
	},
	{
		'desc': 'email',
		'type': 'regex',
		'regex1': r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)',
		'match': 'single_regex',
		'input_case': 'lower',
		'enable': 'false'
	},
	{
		'desc': 'phone number',
		'type': 'regex',
		'regex1': r'[1]+[34578]+[0-9]{9}',
		'match': 'single_regex',
		'input_case': 'exact',
		'enable': 'false'
	},
	{
		'desc': 'Base64String',
		'type': 'regex',
		'regex1': '^[A-Za-z0-9+/]+[=]{0,2}$',
		'match': 'single_regex',
		'input_case': 'exact',
		'enable': 'true'
	},
	# {
	# 	'desc':'url',
	# 	'type': 'regex',
	# 	'regex1': r'((ht|f)tps?):\/\/{0,1}+[\w\-]+(\.[\w\-]+)+([\w\-.,@?^=%&:\/~+#]*[\w\-@?^=%&\/~+#])?',
	# 	'match': 'single_regex',
	# 	'input_case': 'exact'
	# }
]
def get_list_match_items(ruleset):
	"""Get List of Match item"""
	match_list = []
	i = 1
	identifier = ruleset["type"]
	if ruleset["match"] == 'string_and_or':
		identifier = 'string_or'
	elif ruleset["match"] == 'string_or_and':
		identifier = 'string_and'
	while identifier + str(i) in ruleset:
		match_list.append(ruleset[identifier + str(i)])
		i = i + 1
		if identifier + str(i) in ruleset == False:
			break
	return match_list