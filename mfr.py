import frida
import argparse

parser = argparse.ArgumentParser(prog='mfr')
parser.add_argument('app', help='app package name')
parser.add_argument('-f', '--find', type=str, required=True, help='text to be search')
parser.add_argument('-r', '--replace', type=str, required=True, help='text to be written')
arguments = parser.parse_args()

PACKAGE_NAME = arguments.app
FIND = arguments.find
FIND_HEX_ENCODED = FIND.encode().hex()
REPLACE = arguments.replace

session = frida.get_usb_device().attach(PACKAGE_NAME)

#create the JS snippet
script = session.create_script(
    """
    rpc.exports = {
      enumerateRanges (protection) {
        return Process.enumerateRangesSync(protection);
      },

      searchMemory (address, size, pattern) {
        return Memory.scanSync(ptr(address), size, pattern);
      },

      writeToMemory (address, text) {
        var np = new NativePointer(address);
        np.writeUtf8String(text);
      }
    };
    """)

script.load()
rpc = script.exports

ranges = rpc.enumerate_ranges("rw-")

#This counter will keep track of number of changes.
counter = 0;
for range in ranges:
    base = range["base"] 
    size = range["size"] 
    results = rpc.search_memory(base, size, FIND_HEX_ENCODED)

    for result in results:
        memAddress = result["address"]
        #At each iteration, calls writeToMemory funtion
        rpc.write_to_memory(memAddress, REPLACE)
        print("@" + memAddress + " " + FIND + " was replaced with " + REPLACE + ".")
        counter = counter + 1;

#Show the user how many changes are made
print (str(counter) + " changes are made.");
