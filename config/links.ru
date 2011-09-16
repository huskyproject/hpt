# Link definitions

# используется для локальных обращений к нашей системе
link LoopBack
aka 2:5020/9999.99
allowemptypktpwd on

# пример описания аплинка
link 2:5020/9999
aka 2:5020/9999
ouraka 2:5020/9999.99
password pAs5w0rD
areafixpwd pAs5w0rD
# areafixautocreate on
route direct 2:5020/9999 2:5020/9999.*

