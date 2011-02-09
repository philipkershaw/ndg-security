#
# Simple Wrapper for the ASMap service
#
from AAmap import AAmap
map=AAmap('map_config.xml','ourcert')

def AAWS(command,argument):
    if command=='getTrustedHosts':
        return map.getTrustedHosts(argument)
    elif command=='map':
        #probably need to handle this as a base64 encoded string to
        #ensure future migration to RFC3281 ...
        return map.map(argument)
from ZSI import dispatch
dispatch.AsServer(port=4999)
