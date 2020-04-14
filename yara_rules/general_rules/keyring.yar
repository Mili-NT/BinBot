/*
This is an import of the regular expressions I wrote for Keyring.
*/

rule regex_pattern
{
    strings:
        $gitapi = /[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]/
        $awstoken = /AKIA[0-9A-Z]{16}/
        $googletoken = /ya29.[0-9a-zA-Z_\\-]{68}/
        $googleoauth = /(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")/
        $googleapi = /AIzaSy[0-9a-zA-Z_\\-]{33}/
        $slackapi = /xoxp-\\d+-\\d+-\\d+-[0-9a-f]+/
        $slackwebhook = /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/
        $slackbottoken = /xoxb-\\d+-[0-9a-zA-Z]+/
        $genericapi = /[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]/
        $discordbottoken = /([\w\-\.]+[\-\.][\w\-\.]+)/
        $discordwebhook = /(https:\/\/discordapp\.com\/api\/webhooks\/[\d]+\/[\w]+)/
        $discordnitro = /(https:\/\/discord\.gift\/.+[a-z{1,16}])/
        $herokuapi = /[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/
        $facebookoauth = /[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]/
        $twilioapi = /SK[a-z0-9]{32}/
    condition:
        any of them
}

