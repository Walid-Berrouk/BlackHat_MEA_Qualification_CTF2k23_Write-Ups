# Native imports
from secrets import randbelow
import hashlib

# Non-native imports
from Crypto.Util.number import getStrongPrime     # pip install pycryptodome


# Domain parameters
P = 0xcbbf9c90651da70c4e2764fd11c192f16dd17c1cc72f2e6e416dd286e5683d17a1d94159413b7efaf966c637f271f819bf526ac886f2087e6814010a30aa3f02b05d7d40ada87f3d179b74b2a0db6818888565bf8f896e00a8db138dcca19895cf9cd50acd6dd048e195b8229d4bd4d37ee61369becc7778961edba78e4d0767
G = 0x0dce66dbb7bb3e44dc3dcce4591580b4ca93cdc39ab2c453da73251249929e1a36ebafe59f382518e4479f496a80dc48c6462584eb5c5bf541b28ac5599d973fbbdcbc34049bb2eebc733ea4f63c64f447608213bd751ce660750cd5cc71ef7a84a80ae4f4b2cda655f18293ddebb6568a3fe221a53431dfc03369e76fee8002


# Council Public Keys

council = {
    0: 0x9380fe0eb0c76d20bf69a88b0c5f9aa7faa69f5e0f73df0e547a29fc0e74bd2821573748eb378534b655385ded18baa816e2e9c919e9558174b45271eeee33d0e88f90c86d57fbfc78ada321c53948cf127f6e372b62053af6a5ac5ef80b59167dbcfb754198ada8b0864152305f295c7ad9d728d109f32d111362de26842691,
    1: 0x888053a8586a6db190554d686deb3defed3d56d37a3d9016fd0c90020a1405bb277e13f59a5e034b8a1a53e2e4a7c59cbd4a12fcb269d57c73d865116ace90db2cb5f87d3a925aa8d1fff546ebcffd0138259c51c29c5a3b9e7fdd88b2170afaae5805c54f8e59870bd5db12972f892523c7f38b99514c32faca9ecaf3e76aeb,
    2: 0x1bbfb71714ff074dd37e83a79dc232be8a392af8e5f18096ddd508c19de696eb4e25d8a26550a2c2c4bb9b3fbbd1a7937f806df23bfde805630b441fe0b4c7a139b5175df5f57f2f9b6ef832d1854921f5c31636f5238d86d6bbc0d8d842d36823d68191fe050ae4f28c634fd293cd6e04e1c476e9742fe27f45bb1eeb92a3db,
    3: 0x3dbf9921b03760c031d3864bba46af9cbaba034e9430c9dbf6cf9c3593dec03f5c6dc74a55a56e5842722781da52cf017861cad7349284a22d087e044c2633b48073035525de61828a96da3639f89e3e6449c12999089f5d55d39c1d8b9de06b7b35aac108ae3f0f2949870f495803ba038b759668d2c2321baf370b3c828bba,
    4: 0xa791c6e6fab500c39129590859a2fcf335eab981dbb0ddb9ccd5d5f662e63e397ef55acf28def21c1de582d36b0556556d91cecb12716c6c0fb1e693155027966a92c7229c3a48496854edd547c6893e85fd5eef98f5f1c24c0bd207fd5e520c81b5b5a0c1e11bded6533979f0812a693bfc59bb851fc40240ace65929575370,
    5: 0xb2596bc1cf9d17d17052f4175215fa65d6602c21eff4316a57512193f513d76a4c1f905826e16eb81557a72fed04c035a3c1a319d4b22e74059c2667fc7ad451e67874ada300b2078eec23686744c85287378d571a14a7e5ba53a12030fec183fd5e266f31bf2026a6c2b66570f47a4e66309a75bed7c72092acc11ef5396032,
    6: 0x7785ccd1d2970c87134aadfb576cd8ecce181094fb878f90b5e3b7f6a3d9d30d9e58fe397b5ef52aa3ea10fcae05ac5e71f629cb30b2a50c36c103bf2d12d966e3fa406d89556d681856183df352a74652bc020863f02b1d7458ca55036547fc919906c8b5e78d111655aaa53182f465967af2ed32e0c05474ac4065ff3b73d3,
    7: 0xbfa897175b1d682286b4874efd66e1584aac8679d5a3111e742cf0c850ab3c1365a57a3d8709e0be588feac318e0bea2f5d2c6ac4aaa9a5ce3e297d947952be3bbb03d6a8ba5caba8f6e27a6d6c557b400ebb4ac426f95feca3883169c6f7229bdb21b01de6142034bf6a776fe9f205fbafae21f25b803db7f3a70bf35deaa44

}

# Generate Keys

# Council member class
class Member:
    def __init__(self, public: int = 0):
        self.private = randbelow(P)
        self.public  = pow(G, self.private, P)
        self.r = None
        
    def __aggregate(self, members):
        key = 1
        for memberPub in members:
            key *= memberPub
            key %= P
        return key

    def __hash(self, ctx, inputs):
        x = [str(ctx).encode()]
        for y in inputs:
            if isinstance(y, int):
                x += [y.to_bytes(-(-y.bit_length() // 8), 'big')]
            elif isinstance(y, bytes):
                x += [y]
            else:
                x += [str(y).encode()]
        return hashlib.sha256(b'::'.join(x)).digest()
    
    def generateCommitment(self):
        self.r = randbelow(P)
        R = pow(G, self.r, P)
        t = self.__hash('COM', [R]).hex()
        return R, t
    
    def verifyCommitments(self, R, t):
        return all(t[i] == self.__hash('COM', [R[i]]).hex() for i in range(max(len(R), len(t))))

    def generateSignature(self, members, R, m):
        x = 1
        for i in R:
            x *= i
            x %= P
        c = self.__hash('SIG', [self.__aggregate(members), x, m])
        s = (self.r + int.from_bytes(c, 'big') * self.private) % (P - 1)
        self.r = None
        return s
    
    def verifySignature(self, sig):
        assert set(sig) == {'L', 'R', 'S', 'm'}
        L, R, S = [int(sig[i], 16) for i in 'LRS']
        c = int.from_bytes(self.__hash('SIG', [L, R, sig['m']]), 'big')
        return pow(G, S, P) == (R * pow(L, c, P)) % P

# Generate Keys

user = Member()

print('Public= 0x{:0256x}'.format(user.public))
print('Private= 0x{:0256x}'.format(user.private))


# Commitment

R, t = user.generateCommitment()

print('R= 0x{:0256x}'.format(R))
print('t= ', t)

# Council R Values
# |  ~ Council public R values:
# |    0: 0x439a25bdf281b399de22cf67f420bffbbbec51dc816ed8ddea86b7e9452f7ddd082ca2793207b72896909ed4d680af36e98e495e1cab11b219aad2922ce29b98557925687541408ea710e9d2f5fabe6596df4838ac92569dc8a82f4685717dbd3ee98dbe214f3eadf7fd46337668fb99b2310c30e48a291144b3538a22278e11
# |    1: 0x93b17d7505ffb792988f7b7a9cb1f4c8360d40b1a333f435494fb8fa6ffe7d569c406ded161aa9c355740f472d75e485b4301aee35a3a1e7f3feca5000e96221b1b9f56435f20bb538474d3b72d048dc6033b4e201ae83ca69b44989e5d7ffcabd7d0ea1139326b5cfd1b84806d0238a611b9ce338c8c2030359cbb51bf2394c
# |    2: 0x1201e8e081920a3686b38a43cef9bb3ad0769b42764b6edefc59d12bc37d4fdd941baad460fa9877a11e9086d98e7ba929225bf655c547119d2ab3437fa7cea9133c0d6baaa9d56d6e5675a0a0713e96061818c148b020f279583ea384fb96c56f157dc43a6f8e9250cd6792723287941e63aac279ef1cdc5bc86e9625686ce5
# |    3: 0x898d51f2c894798bcc0fd09e4e93e211563fce3bef063f73b5e1f6de08d3c1f547fc17d028376495da8483dd19acaa7618d7ef8d7d297f21b3691c0e09f1dd52d671b5dbd520e0dc8e64720e7ae2cb96ffc53920a0a7b2e77b847963b2f325a3d3eb7d8ed2028a95d7eed485be7ca7a4e2f030a9402bc18298caaf4d6260a5fd
# |    4: 0x54057725b1462e633a65c08cca0e89aee8dca3dedc17af302ef6eb1703fb59f210d5db4e2d385345d827e849915073c254de05e0b3e1a2c1dc367668865436e1c6060a89b1c5888d648e067080bab3f9859450dfa22c437703171a98f8ceae56f53b2aa313b5af89d8f913e93e1c412e635ca421273c432c72a2a33a18d759b5
# |    5: 0xbadaebc74f4c424abfe2f8f673ccab157e35eed8314b43889844f9acfc0135f55df6a614b0436a5dd7dec21db49970a4436bd16658ee8ff60480ddacda3fb9f0437afd1d9ccbc7bf0333626c19b8aa459e75efbf84e9db95ff3999fffe5ed3b3416ae23c14c813785e52872b7182fccf424a35799255745d30918d72ccb37897
# |    6: 0x596ba47164e44b93fe7e7da174e782032fbc949e7fbcb8ebe9a326f1d2354e4e9e493dfa2a9b46cf745430ba3f92ff49213ab11cfd2068cd16e92967d2a80438511d1a5ece0b37cda8b931550a1e0ad553ea9a0371feed0a0469bc7c7899163c2c426bbab2a9c0d41d6670b0b9d7e1b605bea47ad9a2266898519c30f48cbd5f
# |    7: 0x1a8f795ba9cca167999f5e7bc78f47ef4a44430b109f8b6a631882d61b2bfecfc7d8bd46c17d99941de45287ebd66575a81ef8dc7e7cad86e9aa127bcd4db7b9ee8120cbd6ea5d8498f43918a616c3f6066a5b9822f79a4dddfccc90dcf8a1ca0e283fed3cec519203ef2b4d77f861636ec7a0636635b83e9d4d86f6f2307279


# # Council Commitments t

# |  ~ Council commitments:
# |    0: b19a5d468d469f2402bb6b222c9814d86c515d01c9db77f2e194d58269236350
# |    1: 5ac74db0532f6f1130a8e3d0c2c659af16105d1f9a6c91f9e2be985b001fc1b8
# |    2: 3f235b8057d1c988fcd499b6d4bd3ff9315c8b14ea5a22d7b2d16970db02b9a1
# |    3: e6f3d79847b9b626159261bafe4d5c292c2d8042a673d7997bc687cadff17203
# |    4: fa0a79d6882b747f5486abe3bf9bb548f0d1cc8892b53e339d7d1b9ddb423399
# |    5: c19cf825a23ecd9eefb01661e1efb29726532c25d894cf5a21b0f30ab870a98e
# |    6: 33b8e9d4fd0cace8994cd80e4cf504e11d58da6441f1f340ab8a7ec3d9e511fa
# |    7: 23a775ff92f57eb915de9ba4e38b869cc04e3bdb248e0332bd65a2de7f56a934
# |
# |

# # Message

# userMessage = 'Can I hab flag plz?'

# # Signature

# S = user.generateSignature(council + [user], councilRs + [R], userMessage)