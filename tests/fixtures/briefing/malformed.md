# Malformed briefing

## Targets

this line has no bullet marker so it is ignored
- 10.10.10.5
- not-an-ip-but-fine-as-hint

## Credentials

| user | kind | secret |
| --- | --- | --- |
| alice | password | hunter2 |
garbage row with no pipes
| bob | NTLM | aad3b435b51404eeaad3b435b51404ee |

## NotASection

stray content with a non-canonical header — should be tolerated

## Notes

partial notes ok
