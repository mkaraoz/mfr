import textwrap
import frida
import frida.core
import argparse

# about rpc method calls: https://github.com/frida/frida-python/issues/104

#arg parser
def getParams():
    parser = argparse.ArgumentParser(
        prog='text-search',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('process',
                        help='the process that you will be injecting to')
    parser.add_argument('-f', '--find', type=str, required=True,
                        help='text that will be replaced')
    parser.add_argument('-r', '--replacement', type=str, required=True,
                        help='text that will replace old text')
    args = parser.parse_args()
    return args

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

arguments = getParams()
APP_NAME = arguments.process
OLD_TEXT = arguments.find
# If the new text is longer than the old text writeUtf8String() may
# cause a buffer-overflow and may corrupt unrelated memory.
NEW_TEXT = arguments.replacement
PERMS = 'w' 

session = None
try:
    session = frida.get_usb_device().attach(APP_NAME)
    print("connecte to process " + APP_NAME)
except Exception as e:
    print("Can't connect to App. Have you connected the device?")
    logging.debug(str(e))
    sys.exit()

print("Starting memory search...")

script = session.create_script(
    """'use strict';
    rpc.exports = {
      enumerateRanges: function (prot) {
        return Process.enumerateRangesSync(prot);
      },

      searchMemory: function (address, size, pattern) {
        return Memory.scanSync(ptr(address), size, pattern);
      },

      writeToMemory: function (address, text) {
        var np = new NativePointer(address);
        np.writeUtf8String(text);
      }
     };
    """)

script.on("message", on_message)
script.load()

agent = script.exports
ranges = agent.enumerate_ranges(PERMS)

# Performing the memory search
counter = 0;
for range in ranges:
    base = range["base"]
    size = range["size"]
    results = agent.search_memory(base, size, OLD_TEXT.encode("utf-8").hex())
    for result in results:
        memAddress = result["address"]
        agent.write_to_memory(memAddress, NEW_TEXT)
        print("@" + base + " replaced " + OLD_TEXT + " with " + NEW_TEXT)
        counter=counter+1;

print ("Replaced " + str(counter) + " strings.");
