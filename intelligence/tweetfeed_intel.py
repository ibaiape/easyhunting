from py_console import console, bgColor, textColor
import pandas as pd

from utils.colors import colors

def get_tweetfeed_iocs(ioc):
	feed = pd.read_csv('https://github.com/0xDanielLopez/TweetFeed/raw/master/year.csv', header=None)
	result = list()
	matches = feed.loc[feed[3].str.contains(ioc, na=False)]
	matches_cleaned = matches.fillna('') # remove NaN values
	if matches_cleaned.empty:
		return
	for row in matches_cleaned.itertuples():
		ioc = dict()
		ioc['date'] = row[1]
		ioc['researcher'] = row[2]
		ioc['ioc_type'] = row[3]
		ioc['ioc'] = row[4]
		ioc['tags'] = row[5]
		ioc['tweet'] = row[6]
		result.append(ioc)
	return result
	

def tweetfeed_ioc_search(ioc, banner=True):
	report = get_tweetfeed_iocs(ioc)
	if not report:
		return
	if banner:
		print(f'intel from {console.highlight("tweetfeed", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	result2print = 5
	for ioc in report[:result2print]:
		print(f'\t{colors.ATTENTION}' + str(ioc.get('ioc')) + f'{colors.RESET}')
		print('\ttype: ' + str(ioc.get('ioc_type')))
		print('\tresearcher: ' + str(ioc.get('researcher')))
		print('\tpublished: ' + str(ioc.get('date')))
		if ioc.get('tags'):
			print('\ttags: ', end = '')
			for tag in ioc.get('tags').replace(' ', '').split('#'):
				print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
			print()
		print('\ttweet: ' + str(ioc.get('tweet')) + '\n')
	if len(report) > result2print:
		print('\tthere are more matched iocs!')
		print('\tyou can find them in https://tweetfeed.live/' + '\n')

def tweetfeed_print_tags(ioc):
	tags = tweetfeed_tags(ioc)
	if tags:
		print(f'{console.highlight("tweetfeed", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
		print(': ', end=' ')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()

def tweetfeed_tags(ioc):
	report = get_tweetfeed_iocs(ioc)
	if report:
		for ioc in report:
			if ioc.get('tags'):
				tags = set()
				for tag in ioc.get('tags').replace(' ', '').split('#'):
					tags.add(tag)
		return tags			