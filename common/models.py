import traceback
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.contrib.auth import login, logout
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.db.models.signals import pre_save, post_save
import string
import random
from django.urls import reverse
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils import timezone


class Utilities:
    """Generic utilities."""

    @staticmethod
    def to_base32(n):
        """Convert integer to base32."""
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "0" if not n else Utilities.to_base32(n // 32).lstrip("0") + alphabet[n % 32]


class UserManager(UserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User."""

    DEFAULT_EMAIL_FORMAT = 'noemail-{}@vpn.anode.co'

    username = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField(_('Email address'), unique=True)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    user_created_time = models.CharField(max_length=200, null=True, blank=True)
    public_key_id = models.CharField(max_length=32, null=True, blank=True)
    public_key = models.CharField(max_length=150, null=True, blank=True)
    private_key = models.CharField(max_length=64, null=True, blank=True)
    is_confirmed = models.BooleanField(default=False)
    is_backup_wallet_password_seen = models.BooleanField(default=False)
    confirmation_code = models.CharField(max_length=64, null=True, blank=True)
    password_recovery_token = models.CharField(max_length=65, null=True, blank=True)
    backup_wallet_password = models.CharField(max_length=65, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    account_confirmation_status_url = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

    animals = ["Aardvark", "Aardwolf", "Abalone", "Abyssiniancat", "Abyssiniangroundhornbill", "Acaciarat", "Achillestang", "Acornbarnacle", "Acornweevil", "Acornwoodpecker", "Acouchi", "Adamsstaghornedbeetle", "Addax", "Adder", "Adeliepenguin", "Admiralbutterfly", "Adouri", "Aegeancat", "Affenpinscher", "Hound", "Augurbuzzard", "Bushviper", "Civet", "Clawedfrog", "Elephant", "Fisheagle", "Goldencat", "Groundhornbill", "Harrierhawk", "Hornbill", "Jacana", "Molesnake", "Paradiseflycatcher", "Piedkingfisher", "Porcupine", "Rockpython", "Wildcat", "Wilddog", "Agama", "Agouti", "Aidi", "Airedale", "Airedaleterrier", "Akitainu", "Mapturtle", "Jingle", "Husky", "Kleekai", "Malamute", "Albacoretuna", "Albatross", "Albertosaurus", "Albino", "Aldabratortoise", "Allensbigearedbat", "Alleycat", "Alligator", "Alligatorgar", "Alligatorsnappingturtle", "Allosaurus", "Alpaca", "Alpinegoat", "Alpineroadguidetigerbeetle", "Altiplanochinchillamouse", "Amazondolphin", "Amazonparrot", "Amazontreeboa", "Amberpenshell", "Ambushbug", "Alligator", "Avocet", "Badger", "Bittern", "Vulture", "Bobtail", "Bulldog", "Cicada", "Crayfish", "Creamdraft", "Crocodile", "Crow", "Curl", "Goldfinch", "Indianhorse", "Kestrel", "Lobster", "Marten", "Painthorse", "Quarterhorse", "Ratsnake", "Redsquirrel", "Riverotter", "Robin", "Saddlebred", "Shorthair", "Toad", "Warmblood", "Wigeon", "Wirehair", "Amethystgemclam", "Amethystinepython", "Amethystsunbird", "Ammonite", "Amoeba", "Amphibian", "Amphiuma", "Amurminnow", "Amurratsnake", "Amurstarfish", "Anaconda", "Anchovy", "Andalusianhorse", "Andeancat", "Andeancondor", "Anemone", "Anemonecrab", "Anemoneshrimp", "Angelfish", "Angelwingmussel", "Anglerfish", "Angora", "Angwantibo", "Anhinga", "Ankole", "Ankolewatusi", "Annashummingbird", "Annelid", "Annelida", "Anole", "Anophelesmosquito", "Ant", "Antarcticfurseal", "Antarcticgiantpetrel", "Antbear", "Anteater", "Antelope", "Antelopegroundsquirrel", "Antipodesgreenparakeet", "Antlion", "Anura", "Aoudad", "Apatosaur", "Ape", "Aphid", "Apisdorsatalaboriosa", "Aplomadofalcon", "Appaloosa", "Aquaticleech", "Arabianhorse", "Arabianoryx", "Arabianwildcat", "Aracari", "Arachnid", "Arawana", "Archaeocete", "Archaeopteryx", "Archerfish", "Arcticduck", "Arcticfox", "Arctichare", "Arcticseal", "Arcticwolf", "Argali", "Argentinehornedfrog", "Argentineruddyduck", "Argusfish", "Arieltoucan", "Arizonaalligatorlizard", "Arkshell", "Armadillo", "Armedcrab", "Armednylonshrimp", "Armyant", "Armyworm", "Arrowana", "Arrowcrab", "Arrowworm", "Arthropods", "Aruanas", "Constablebutterfly", "Damselfly", "Elephant", "Lion", "Piedstarling", "Porcupine", "Smallclawedotter", "Trumpetfish", "Waterbuffalo", "Greaterfreshwaterclam", "Lesserfreshwaterclam", "Mouflon", "Asp", "Assassinbug", "Astarte", "Astrangiacoral", "Atlanticblackgoby", "Atlanticbluetang", "Atlanticridleyturtle", "Atlanticsharpnosepuffer", "Atlanticspadefish", "Atlasmoth", "Attwatersprairiechicken", "Auk", "Auklet", "Aurochs", "Australiancattledog", "Australiancurlew", "Australianfreshwatercrocodile", "Australianfurseal", "Australiankelpie", "Australiankestrel", "Australianshelduck", "Australiansilkyterrier", "Austrianpinscher", "Avians", "Avocet", "Axisdeer", "Axolotl", "Ayeaye", "Aztecant", "Azurevase", "Azurevasesponge", "Azurewingedmagpie", "Babirusa", "Baboon", "Backswimmer", "Bactrian", "Badger", "Bagworm", "Baiji", "Baldeagle", "Baleenwhale", "Balloonfish", "Ballpython", "Bandicoot", "Bangeltiger", "Bantamrooster", "Banteng", "Barasinga", "Barasingha", "Barb", "Barbet", "Barebirdbat", "Barnacle", "Barnowl", "Barnswallow", "Barracuda", "Basenji", "Basil", "Basilisk", "Bass", "Bassethound", "Bat", "Bats", "Beagle", "Bear", "Beardedcollie", "Beardeddragon", "Beauceron", "Beaver", "Bedbug", "Bedlingtonterrier", "Bee", "Beetle", "Bellfrog", "Bellsnake", "Belugawhale", "Bengaltiger", "Bergerpicard", "Bernesemountaindog", "Betafish", "Bettong", "Bichonfrise", "Bighorn", "Bighornedsheep", "Bighornsheep", "Bigmouthbass", "Bilby", "Binturong", "Bird", "Birdofparadise", "Bison", "Bittern", "Blackbear", "Blackbird", "Blackbuck", "Blackfish", "Blackfly", "Blackfootedferret", "Blacklab", "Blacklemur", "Blackmamba", "Blacknorwegianelkhound", "Blackpanther", "Blackrhino", "Blackrussianterrier", "Blackwidowspider", "Blesbok", "Blobfish", "Blowfish", "Blueandgoldmackaw", "Bluebird", "Bluebottle", "Bluebottlejellyfish", "Bluefintuna", "Bluefish", "Bluegill", "Bluejay", "Blueshark", "Bluet", "Bluetickcoonhound", "Bluetonguelizard", "Bluewhale", "Boa", "Boaconstrictor", "Boar", "Bobcat", "Bobolink", "Bobwhite", "Boilweevil", "Bongo", "Bonobo", "Booby", "Bordercollie", "Borderterrier", "Borer", "Borzoi", "Boto", "Boubou", "Boutu", "Bovine", "Brahmanbull", "Brahmancow", "Brant", "Bream", "Brocketdeer", "Bronco", "Brontosaurus", "Brownbear", "Brownbutterfly", "Bubblefish", "Buck", "Buckeyebutterfly", "Budgie", "Bufeo", "Buffalo", "Bufflehead", "Bug", "Bull", "Bullfrog", "Bullmastiff", "Bumblebee", "Bunny", "Bunting", "Burro", "Bushbaby", "Bushsqueaker", "Bustard", "Butterfly", "Buzzard", "Caecilian", "Caiman", "Caimanlizard", "Calf", "Camel", "Canadagoose", "Canary", "Canine", "Canvasback", "Capeghostfrog", "Capybara", "Caracal", "Cardinal", "Caribou", "Carp", "Carpenterant", "Cassowary", "Cat", "Catbird", "Caterpillar", "Catfish", "Cats", "Cattle", "Caudata", "Cavy", "Centipede", "Cero", "Chafer", "Chameleon", "Chamois", "Chanticleer", "Cheetah", "Chevrotain", "Chick", "Chickadee", "Chicken", "Chihuahua", "Chimneyswift", "Chimpanzee", "Chinchilla", "Chinesecrocodilelizard", "Chipmunk", "Chital", "Chrysalis", "Chrysomelid", "Chuckwalla", "Chupacabra", "Cicada", "Cirriped", "Civet", "Clam", "Cleanerwrasse", "Clingfish", "Clownanemonefish", "Clumber", "Coati", "Cob", "Cobra", "Cockerspaniel", "Cod", "Coelacanth", "Collardlizard", "Collie", "Colt", "Comet", "Commabutterfly", "Commongonolek", "Conch", "Condor", "Coney", "Conure", "Cony", "Coot", "Cooter", "Copepod", "Copperbutterfly", "Copperhead", "Coqui", "Coral", "Cormorant", "Cornsnake", "Corydorascatfish", "Cottonmouth", "Cottontail", "Cow", "Cowbird", "Cowrie", "Coyote", "Coypu", "Crab", "Crane", "Cranefly", "Crayfish", "Creature", "Cricket", "Crocodile", "Crocodileskink", "Crossbill", "Crow", "Crownofthornsstarfish", "Crustacean", "Cub", "Cuckoo", "Cur", "Curassow", "Curlew", "Cuscus", "Cusimanse", "Cuttlefish", "Cutworm", "Cygnet", "Dachshund", "Dalmatian", "Damselfly", "Danishswedishfarmdog", "Darklingbeetle", "Dartfrog", "Darwinsfox", "Dassie", "Dassierat", "Davidstiger", "Deer", "Deermouse", "Degu", "Degus", "Deinonychus", "Desertpupfish", "Devilfish", "Deviltasmanian", "Diamondbackrattlesnake", "Dikdik", "Dikkops", "Dingo", "Dinosaur", "Diplodocus", "Dipper", "Discus", "Dobermanpinscher", "Doctorfish", "Dodo", "Dodobird", "Doe", "Dog", "Dogfish", "Dolphin", "Donkey", "Dorado", "Dore", "Dorking", "Dormouse", "Dotterel", "Dove", "Dowitcher", "Drafthorse", "Dragon", "Dragonfly", "Drake", "Drever", "Dromaeosaur", "Dromedary", "Drongo", "Duck", "Duckbillcat", "Duckbillplatypus", "Duckling", "Dugong", "Duiker", "Dunlin", "Dunnart", "Dutchshepherddog", "Dutchsmoushond", "Eagle", "Earthworm", "Earwig", "Easternglasslizard", "Easternnewt", "Echidna", "Eel", "Eelelephant", "Eeve", "Eft", "Egg", "Egret", "Eider", "Eidolonhelvum", "Ekaltadeta", "Eland", "Electriceel", "Elephant", "Elephantbeetle", "Elephantseal", "Elk", "Elkhound", "Elver", "Emeraldtreeskink", "Emperorpenguin", "Emperorshrimp", "Emu", "Englishpointer", "Englishsetter", "Equestrian", "Equine", "Erin", "Ermine", "Erne", "Eskimodog", "Esok", "Estuarinecrocodile", "Ethiopianwolf", "Europeanfiresalamander", "Europeanpolecat", "Ewe", "Eyas", "Eyelashpitviper", "Eyra", "Fairybluebird", "Fairyfly", "Falcon", "Fallowdeer", "Fantail", "Fanworms", "Fattaileddunnart", "Fawn", "Feline", "Fennecfox", "Ferret", "Fiddlercrab", "Fieldmouse", "Fieldspaniel", "Finch", "Finnishspitz", "Finwhale", "Fireant", "Firebelliedtoad", "Firecrest", "Firefly", "Fish", "Fishingcat", "Flamingo", "Flatcoatretriever", "Flatfish", "Flea", "Flee", "Flicker", "Flickertailsquirrel", "Flies", "Flounder", "Fluke", "Fly", "Flycatcher", "Flyingfish", "Flyingfox", "Flyinglemur", "Flyingsquirrel", "Foal", "Fossa", "Fowl", "Fox", "Foxhound", "Foxterrier", "Frenchbulldog", "Freshwatereel", "Frigatebird", "Frilledlizard", "Frillneckedlizard", "Fritillarybutterfly", "Frog", "Frogmouth", "Fruitbat", "Fruitfly", "Fugu", "Fulmar", "Funnelweaverspider", "Furseal", "Gadwall", "Galago", "Galah", "Galapagosalbatross", "Galapagosdove", "Galapagoshawk", "Galapagosmockingbird", "Galapagospenguin", "Galapagossealion", "Galapagostortoise", "Gallinule", "Gallowaycow", "Gander", "Gangesdolphin", "Gannet", "Gar", "Gardensnake", "Garpike", "Gartersnake", "Gaur", "Gavial", "Gazelle", "Gecko", "Geese", "Gelada", "Gelding", "Gemsbok", "Gemsbuck", "Genet", "Gentoopenguin", "Gerbil", "Gerenuk", "Germanpinscher", "Germanshepherd", "Germanshorthairedpointer", "Germanspaniel", "Germanspitz", "Germanwirehairedpointer", "Gharial", "Ghostshrimp", "Giantschnauzer", "Gibbon", "Gilamonster", "Giraffe", "Glassfrog", "Globefish", "Glowworm", "Gnat", "Gnatcatcher", "Gnu", "Goa", "Goat", "Godwit", "Goitered", "Goldeneye", "Goldenmantledgroundsquirrel", "Goldenretriever", "Goldfinch", "Goldfish", "Gonolek", "Goose", "Goosefish", "Gopher", "Goral", "Gordonsetter", "Gorilla", "Goshawk", "Gosling", "Gossamerwingedbutterfly", "Gourami", "Grackle", "Grasshopper", "Grassspider", "Grayfox", "Grayling", "Grayreefshark", "Graysquirrel", "Graywolf", "Greatargus", "Greatdane", "Greathornedowl", "Greatwhiteshark", "Grebe", "Greendarnerdragonfly", "Greyhounddog", "Grison", "Grizzlybear", "Grosbeak", "Groundbeetle", "Groundhog", "Grouper", "Grouse", "Grub", "Grunion", "Guanaco", "Guernseycow", "Guillemot", "Guineafowl", "Guineapig", "Gull", "Guppy", "Gyrfalcon", "Hackee", "Haddock", "Hadrosaurus", "Hagfish", "Hairstreak", "Hairstreakbutterfly", "Hake", "Halcyon", "Halibut", "Halicore", "Hamadryad", "Hamadryas", "Hammerheadbird", "Hammerheadshark", "Hammerkop", "Hamster", "Hanumanmonkey", "Hapuka", "Hapuku", "Harborporpoise", "Harborseal", "Hare", "Harlequinbug", "Harpseal", "Harpyeagle", "Harrier", "Harrierhawk", "Hart", "Hartebeest", "Harvestmen", "Harvestmouse", "Hatchetfish", "Hawaiianmonkseal", "Hawk", "Hectorsdolphin", "Hedgehog", "Heifer", "Hellbender", "Hen", "Herald", "Herculesbeetle", "Hermitcrab", "Heron", "Herring", "Hind", "Hippopotamus", "Hoatzin", "Hochstettersfrog", "Hog", "Hogget", "Hoiho", "Hoki", "Homalocephale", "Honeybadger", "Honeybee", "Honeycreeper", "Honeyeater", "Hookersealion", "Hoopoe", "Hornbill", "Hornedtoad", "Hornedviper", "Hornet", "Hornshark", "Horse", "Horsechestnutleafminer", "Horsefly", "Horsemouse", "Horseshoebat", "Horseshoecrab", "Hound", "Housefly", "Hoverfly", "Howlermonkey", "Huemul", "Huia", "Human", "Hummingbird", "Humpbackwhale", "Husky", "Hydatidtapeworm", "Hydra", "Hyena", "Hylaeosaurus", "Hypacrosaurus", "Hypsilophodon", "Hyracotherium", "Hyrax", "Iaerismetalmark", "Ibadanmalimbe", "Iberianbarbel", "Iberianchiffchaff", "Iberianemeraldlizard", "Iberianlynx", "Iberianmidwifetoad", "Iberianmole", "Iberiannase", "Ibex", "Ibis", "Ibisbill", "Ibizanhound", "Iceblueredtopzebra", "Icefish", "Icelandgull", "Icelandichorse", "Icelandicsheepdog", "Ichidna", "Ichneumonfly", "Ichthyosaurs", "Ichthyostega", "Icterinewarbler", "Iggypops", "Iguana", "Iguanodon", "Illadopsis", "Ilsamochadegu", "Imago", "Impala", "Imperatorangel", "Imperialeagle", "Incatern", "Inchworm", "Indianabat", "Indiancow", "Indianelephant", "Indianglassfish", "Indianhare", "Indianjackal", "Indianpalmsquirrel", "Indianpangolin", "Indianrhinoceros", "Indianringneckparakeet", "Indianrockpython", "Indianskimmer", "Indianspinyloach", "Indigobunting", "Indigowingedparrot", "Indochinahogdeer", "Indochinesetiger", "Indri", "Indusriverdolphin", "Inexpectatumpleco", "Inganue", "Insect", "Intermediateegret", "Invisiblerail", "Iraniangroundjay", "Iridescentshark", "Iriomotecat", "Irishdraughthorse", "Irishredandwhitesetter", "Irishsetter", "Irishterrier", "Irishwaterspaniel", "Irishwolfhound", "Irrawaddydolphin", "Irukandjijellyfish", "Isabellineshrike", "Isabellinewheatear", "Islandcanary", "Islandwhistler", "Isopod", "Italianbrownbear", "Italiangreyhound", "Ivorybackedwoodswallow", "Ivorybilledwoodpecker", "Ivorygull", "Izuthrush", "Jabiru", "Jackal", "Jackrabbit", "Jaeger", "Jaguar", "Jaguarundi", "Janenschia", "Japanesebeetle", "Javalina", "Jay", "Jellyfish", "Jenny", "Jerboa", "Joey", "Johndory", "Juliabutterfly", "Jumpingbean", "Junco", "Junebug", "Kagu", "Kakapo", "Kakarikis", "Kangaroo", "Karakul", "Katydid", "Kawala", "Kentrosaurus", "Kestrel", "Kid", "Killdeer", "Killerwhale", "Killifish", "Kingbird", "Kingfisher", "Kinglet", "Kingsnake", "Kinkajou", "Kiskadee", "Kissingbug", "Kite", "Kitfox", "Kitten", "Kittiwake", "Kitty", "Kiwi", "Koala", "Koalabear", "Kob", "Kodiakbear", "Koi", "Komododragon", "Koodoo", "Kookaburra", "Kouprey", "Krill", "Kronosaurus", "Kudu", "Kusimanse", "Labradorretriever", "Lacewing", "Ladybird", "Ladybug", "Lamb", "Lamprey", "Langur", "Lark", "Larva", "Laughingthrush", "Lcont", "Leafbird", "Leafcutterant", "Leafhopper", "Leafwing", "Leech", "Lemming", "Lemur", "Leonberger", "Leopard", "Leopardseal", "Leveret", "Lhasaapso", "Liger", "Lightningbug", "Limpet", "Limpkin", "Ling", "Lion", "Lionfish", "Littlenightmonkeys", "Lizard", "Llama", "Lobo", "Lobster", "Locust", "Loggerheadturtle", "Longhorn", "Longhornbeetle", "Longspur", "Loon", "Lorikeet", "Loris", "Louse", "Lovebird", "Lowchen", "Lunamoth", "Lungfish", "Lynx", "Macaque", "Macaw", "Macropod", "Magpie", "Maiasaura", "Majungatholus", "Malamute", "Mallard", "Maltesedog", "Mamba", "Mamenchisaurus", "Mammal", "Mammoth", "Manatee", "Mandrill", "Mangabey", "Manta", "Mantaray", "Mantid", "Mantis", "Mantisray", "Manxcat", "Mara", "Marabou", "Marbledmurrelet", "Mare", "Marlin", "Marmoset", "Marmot", "Marten", "Martin", "Massasauga", "Massospondylus", "Mastiff", "Mastodon", "Mayfly", "Meadowhawk", "Meadowlark", "Mealworm", "Meerkat", "Megalosaurus", "Megaraptor", "Merganser", "Merlin", "Metalmarkbutterfly", "Metamorphosis", "Microvenator", "Midge", "Milksnake", "Milkweedbug", "Millipede", "Minibeast", "Mink", "Minnow", "Mite", "Moa", "Mockingbird", "Mole", "Mollies", "Mollusk", "Molly", "Monarch", "Mongoose", "Monkey", "Monkfish", "Monoclonius", "Montanoceratops", "Moorhen", "Moose", "Moray", "Morayeel", "Morpho", "Mosasaur", "Mosquito", "Moth", "Motmot", "Mouflon", "Mountaincat", "Mountainlion", "Mouse", "Mousebird", "Mudpuppy", "Mule", "Mullet", "Muntjac", "Murrelet", "Muskox", "Muskrat", "Mussaurus", "Mussel", "Mustang", "Mutt", "Myna", "Mynah", "Myotis", "Nabarlek", "Nag", "Naga", "Nagapies", "Nandine", "Nandoo", "Nandu", "Narwhal", "Narwhale", "Natterjacktoad", "Nauplius", "Nautilus", "Needlefish", "Needletail", "Nematode", "Nene", "Neonblueguppy", "Neonbluehermitcrab", "Neondwarfgourami", "Neonrainbowfish", "Neonredguppy", "Neontetra", "Nerka", "Nettlefish", "Newfoundlanddog", "Newt", "Newtnutria", "Nightcrawler", "Nighthawk", "Nightheron", "Nightingale", "Nightjar", "Nilgai", "Armadillo", "Noctilio", "Noctule", "Noddy", "Noolbenger", "Northerncardinals", "Northernelephantseal", "Northernflyingsquirrel", "Northernfurseal", "Northernpike", "Northernseahorse", "Northernspottedowl", "Norwaylobster", "Norwayrat", "Nubiangoat", "Nudibranch", "Numbat", "Nurseshark", "Nutcracker", "Nuthatch", "Nutria", "Nyala", "Ocelot", "Octopus", "Okapi", "Olingo", "Olm", "Opossum", "Orangutan", "Orca", "Oregonsilverspotbutterfly", "Oriole", "Oropendola", "Oropendula", "Oryx", "Osprey", "Ostracod", "Ostrich", "Otter", "Ovenbird", "Owl", "Owlbutterfly", "Ox", "Oxen", "Oxpecker", "Oyster", "Ozarkbigearedbat", "Paca", "Pachyderm", "Pacificparrotlet", "Paddlefish", "Paintedladybutterfly", "Panda", "Pangolin", "Panther", "Paperwasp", "Papillon", "Parakeet", "Parrot", "Partridge", "Peacock", "Peafowl", "Peccary", "Pekingese", "Pelican", "Pelicinuspetrel", "Penguin", "Perch", "Peregrinefalcon", "Pewee", "Phalarope", "Pharaohhound", "Pheasant", "Phoebe", "Phoenix", "Pigeon", "Piglet", "Pika", "Pike", "Pikeperch", "Pilchard", "Pinemarten", "Pinkriverdolphin", "Pinniped", "Pintail", "Pipistrelle", "Pipit", "Piranha", "Pitbull", "Pittabird", "Plainsqueaker", "Plankton", "Planthopper", "Platypus", "Plover", "Polarbear", "Polecat", "Polyp", "Polyturator", "Pomeranian", "Pondskater", "Pony", "Pooch", "Poodle", "Porcupine", "Porpoise", "Portuguesemanofwar", "Possum", "Prairiedog", "Prawn", "Prayingmantid", "Prayingmantis", "Primate", "Pronghorn", "Pseudodynerusquadrisectus", "Ptarmigan", "Pterodactyls", "Pterosaurs", "Puffer", "Pufferfish", "Puffin", "Pug", "Pullet", "Puma", "Pupa", "Pupfish", "Puppy", "Purplemarten", "Pygmy", "Python", "Quadrisectus", "Quagga", "Quahog", "Quail", "Queenalexandrasbirdwing", "Queenalexandrasbirdwingbutterfly", "Queenant", "Queenbee", "Queenconch", "Queenslandgrouper", "Queenslandheeler", "Queensnake", "Quelea", "Quetzal", "Quetzalcoatlus", "Quillback", "Quinquespinosus", "Quokka", "Quoll", "Rabbit", "Rabidsquirrel", "Raccoon", "Racer", "Racerunner", "Ragfish", "Rail", "Rainbowfish", "Rainbowlorikeet", "Rainbowtrout", "Ram", "Raptors", "Rasbora", "Rat", "Ratfish", "Rattail", "Rattlesnake", "Raven", "Ray", "Redhead", "Redheadedwoodpecker", "Redpoll", "Redstart", "Redtailedhawk", "Reindeer", "Reptile", "Reynard", "Rhea", "Rhesusmonkey", "Rhino", "Rhinoceros", "Rhinocerosbeetle", "Rhodesianridgeback", "Ringtailedlemur", "Ringworm", "Riograndeescuerzo", "Roach", "Roadrunner", "Roan", "Robberfly", "Robin", "Rockrat", "Rodent", "Roebuck", "Roller", "Rook", "Rooster", "Rottweiler", "Sable", "Sableantelope", "Sablefish", "Saiga", "Sakimonkey", "Salamander", "Salmon", "Saltwatercrocodile", "Sambar", "Samoyeddog", "Sandbarshark", "Sanddollar", "Sanderling", "Sandpiper", "Sapsucker", "Sardine", "Sawfish", "Scallop", "Scarab", "Scarletibis", "Scaup", "Schapendoes", "Schipperke", "Schnauzer", "Scorpion", "Scoter", "Screamer", "Seabird", "Seagull", "Seahog", "Seahorse", "Seal", "Sealion", "Seamonkey", "Seaslug", "Seaurchin", "Senegalpython", "Seriema", "Serpent", "Serval", "Shark", "Shearwater", "Sheep", "Sheldrake", "Shelduck", "Shibainu", "Shihtzu", "Shorebird", "Shoveler", "Shrew", "Shrike", "Shrimp", "Siamang", "Siamesecat", "Siberiantiger", "Sidewinder", "Sifaka", "Silkworm", "Silverfish", "Silverfox", "Silversidefish", "Siskin", "Skimmer", "Skipper", "Skua", "Skylark", "Sloth", "Slothbear", "Slug", "Smelts", "Smew", "Snail", "Snake", "Snipe", "Snoutbutterfly", "Snowdog", "Snowgeese", "Snowleopard", "Snowmonkey", "Snowyowl", "Sockeyesalmon", "Solenodon", "Solitaire", "Songbird", "Sora", "Southernhairnosedwombat", "Sow", "Spadefoot", "Sparrow", "Sphinx", "Spider", "Spidermonkey", "Spiketail", "Spittlebug", "Sponge", "Spoonbill", "Spotteddolphin", "Spreadwing", "Springbok", "Springpeeper", "Springtail", "Squab", "Squamata", "Squeaker", "Squid", "Squirrel", "Stag", "Stagbeetle", "Stallion", "Starfish", "Starling", "Steed", "Steer", "Stegosaurus", "Stickinsect", "Stickleback", "Stilt", "Stingray", "Stinkbug", "Stinkpot", "Stoat", "Stonefly", "Stork", "Stud", "Sturgeon", "Sugarglider", "Sulphurbutterfly", "Sunbear", "Sunbittern", "Sunfish", "Swallow", "Swallowtail", "Swallowtailbutterfly", "Swan", "Swellfish", "Swift", "Swordfish", "Tadpole", "Tahr", "Takin", "Tamarin", "Tanager", "Tapaculo", "Tapeworm", "Tapir", "Tarantula", "Tarpan", "Tarsier", "Taruca", "Tasmaniandevil", "Tasmaniantiger", "Tattler", "Tayra", "Teal", "Tegus", "Teledu", "Tench", "Tenrec", "Termite", "Tern", "Terrapin", "Terrier", "Thoroughbred", "Thrasher", "Thrip", "Thrush", "Thunderbird", "Thylacine", "Tick", "Tiger", "Tigerbeetle", "Tigermoth", "Tigershark", "Tilefish", "Tinamou", "Titi", "Titmouse", "Toad", "Toadfish", "Tomtit", "Topi", "Tortoise", "Toucan", "Towhee", "Tragopan", "Treecreeper", "Trex", "Triceratops", "Trogon", "Trout", "Trumpeterbird", "Trumpeterswan", "Tsetsefly", "Tuatara", "Tuna", "Turaco", "Turkey", "Turnstone", "Turtle", "Turtledove", "Uakari", "Ugandakob", "Uintagroundsquirrel", "Ulyssesbutterfly", "Umbrellabird", "Umbrette", "Unau", "Ungulate", "Unicorn", "Upupa", "Urchin", "Urial", "Uromastyxmaliensis", "Uromastyxspinipes", "Urson", "Urubu", "Urus", "Urutu", "Urva", "Utahprairiedog", "Vampirebat", "Vaquita", "Veery", "Velociraptor", "Velvetcrab", "Velvetworm", "Venomoussnake", "Verdin", "Vervet", "Viceroybutterfly", "Vicuna", "Viper", "Viperfish", "Vipersquid", "Vireo", "Virginiaopossum", "Vixen", "Vole", "Volvox", "Vulpesvelox", "Vulpesvulpes", "Vulture", "Walkingstick", "Wallaby", "Wallaroo", "Walleye", "Walrus", "Warbler", "Warthog", "Wasp", "Waterboatman", "Waterbuck", "Waterbuffalo", "Waterbug", "Waterdogs", "Waterdragons", "Watermoccasin", "Waterstrider", "Waterthrush", "Wattlebird", "Watussi", "Waxwing", "Weasel", "Weaverbird", "Weevil", "Westafricanantelope", "Whale", "Whapuku", "Whelp", "Whimbrel", "Whippet", "Whippoorwill", "Whitebeakeddolphin", "Whiteeye", "Whitepelican", "Whiterhino", "Whitetaileddeer", "Whitetippedreefshark", "Whooper", "Whoopingcrane", "Widgeon", "Widowspider", "Wildcat", "Wildebeast", "Wildebeest", "Willet", "Wireworm", "Wisent", "Wobbegongshark", "Wolf", "Wolfspider", "Wolverine", "Wombat", "Woodborer", "Woodchuck", "Woodnymphbutterfly", "Woodpecker", "Woodstorks", "Woollybearcaterpillar", "Worm", "Wrasse", "Wreckfish", "Wren", "Wrenchbird", "Wryneck", "Wuerhosaurus", "Wyvern", "Xanclomys", "Xanthareel", "Xantus", "Xantusmurrelet", "Xeme", "Xenarthra", "Xenoposeidon", "Xenops", "Xenopterygii", "Xenopus", "Xenotarsosaurus", "Xenurusunicinctus", "Xerus", "Xiaosaurus", "Xinjiangovenator", "Xiphias", "Xiphiasgladius", "Xiphosuran", "Xoloitzcuintli", "Xoni", "Xrayfish", "Xraytetra", "Xuanhanosaurus", "Xuanhuaceratops", "Xuanhuasaurus", "Yaffle", "Yak", "Yapok", "Yardant", "Yearling", "Yellowbelliedmarmot", "Yellowbellylizard", "Yellowhammer", "Yellowjacket", "Yellowlegs", "Yellowthroat", "Yellowwhitebutterfly", "Yeti", "Ynambu", "Yorkshireterrier", "Yosemitetoad", "Yucker", "Zander", "Zanzibardaygecko", "Zebra", "Zebradove", "Zebrafinch", "Zebrafish", "Zebralongwingbutterfly", "Zebraswallowtailbutterfly", "Zebratailedlizard", "Zebu", "Zenaida", "Zeren", "Zethusspinipes", "Zethuswasp", "Zigzagsalamander", "Zonetailedpigeon", "Zooplankton", "Zopilote", "Zorilla"]
    adjectives = ["Able", "Absolute", "Academic", "Acceptable", "Acclaimed", "Accomplished", "Accurate", "Aching", "Acidic", "Acrobatic", "Adorable", "Adventurous", "Babyish", "Back", "Baggy", "Bare", "Basic", "Beautiful", "Belated", "Beloved", "Bitter", "Calculating", "Calm", "Candid", "Canine", "Capital", "Carefree", "Careful", "Careless", "Caring", "Cautious", "Cavernous", "Celebrated", "Charming", "Damp", "Dangerous", "Dapper", "Daring", "Dark", "Darling", "Dazzling", "Deadly", "Deafening", "Dear", "Dearest", "Each", "Eager", "Early", "Earnest", "Easy", "Easygoing", "Ecstatic", "Edible", "Educated", "Elderly", "Fabulous", "Failing", "Faint", "Fair", "Faithful", "Familiar", "Famous", "Fancy", "Fantastic", "Far", "Faraway", "Farflung", "Faroff", "Gargantuan", "Gaseous", "General", "Generous", "Gentle", "Genuine", "Giant", "Giddy", "Gigantic", "Hairy", "Half", "Handmade", "Handsome", "Handy", "Happy", "Happygolucky", "Hard", "Icky", "Icy", "Ideal", "Idealistic", "Identical", "Idle", "Idolized", "Ill", "Jaded", "Jagged", "Jampacked", "Kaleidoscopic", "Keen", "Lanky", "Large", "Last", "Lasting", "Lavish", "Lawful", "Madeup", "Magnificent", "Majestic", "Major", "Mammoth", "Marvelous", "Married", "Naive", "Narrow", "Nasty", "Natural", "Oblong", "Obvious", "Occasional", "Oily", "Palatable", "Pale", "Paltry", "Parallel", "Parched", "Partial", "Passionate", "Past", "Pastel", "Peaceful", "Peppery", "Perfect", "Perfumed", "Quaint", "Qualified", "Radiant", "Ragged", "Rapid", "Rare", "Rash", "Raw", "Recent", "Reckless", "Rectangular", "Safe", "Salty", "Same", "Sandy", "Sane", "Sarcastic", "Sardonic", "Satisfied", "Scaly", "Scarce", "Scary", "Scented", "Scholarly", "Scientific", "Scornful", "Scratchy", "Scrawny", "Second", "Secondary", "Secret", "Selfassured", "Selfreliant", "Sentimental", "Single", "Talkative", "Tall", "Tame", "Tan", "Tangible", "Tart", "Tasty", "Tattered", "Taut", "Tedious", "Teeming", "Ultimate", "Unaware", "Uncommon", "Unconscious", "Understated", "Unequaled", "Vacant", "Vague", "Vain", "Valid", "Wan", "Warlike", "Warm", "Warmhearted", "Warped", "Wary", "Wasteful", "Watchful", "Waterlogged", "Watery", "Wavy", "Weak", "Weird", "Yawning", "Yearly", "Zany", "Active", "Actual", "Adept", "Admirable", "Admired", "Adolescent", "Adorable", "Adored", "Advanced", "Affectionate", "Afraid", "Aged", "Aggravating", "Beneficial", "Best", "Better", "Bewitched", "Big", "Bighearted", "Biodegradable", "Bitesized", "Cheerful", "Cheery", "Chief", "Chilly", "Chubby", "Circular", "Classic", "Clean", "Clear", "Clearcut", "Clever", "Close", "Closed", "Decent", "Decimal", "Decisive", "Deep", "Defenseless", "Defensive", "Defiant", "Deficient", "Definite", "Definitive", "Delayed", "Delectable", "Delicious", "Elaborate", "Elastic", "Elated", "Electric", "Elegant", "Elementary", "Elliptical", "Fast", "Fatal", "Favorable", "Favorite", "Fearless", "Feisty", "Feline", "Few", "Fickle", "Gifted", "Giving", "Glamorous", "Glaring", "Glass", "Gleaming", "Gleeful", "Glistening", "Glittering", "Gross", "Hardtofind", "Harmful", "Harmless", "Harmonious", "Harsh", "Hasty", "Haunting", "Illustrious", "Imaginary", "Imaginative", "Immaculate", "Immaterial", "Immediate", "Immense", "Impassioned", "Jaunty", "Jealous", "Jittery", "Key", "Kind", "Leading", "Leafy", "Lean", "Left", "Legal", "Legitimate", "Light", "Massive", "Mature", "Meager", "Mealy", "Mean", "Measly", "Meaty", "Medical", "Mediocre", "Nautical", "Near", "Neat", "Necessary", "Needy", "Odd", "Oddball", "Offbeat", "Official", "Old", "Periodic", "Perky", "Personal", "Pertinent", "Pesky", "Pessimistic", "Petty", "Physical", "Piercing", "Pink", "Pitiful", "Plain", "Quarrelsome", "Quarterly", "Ready", "Real", "Realistic", "Reasonable", "Red", "Reflecting", "Regal", "Regular", "Separate", "Serene", "Serious", "Serpentine", "Several", "Severe", "Shabby", "Shadowy", "Shady", "Shallow", "Sharp", "Shimmering", "Shiny", "Shocked", "Shocking", "Shoddy", "Short", "Shortterm", "Showy", "Shrill", "Shy", "Silent", "Silky", "Tempting", "Tender", "Tense", "Tepid", "Terrific", "Testy", "Thankful", "That", "These", "Tremendous", "Uneven", "Unfinished", "Unfolded", "Uniform", "Unique", "Valuable", "Vapid", "Variable", "Vast", "Velvety", "Wealthy", "Weary", "Webbed", "Wee", "Weekly", "Weepy", "Weighty", "Welcome", "Welldocumented", "Yellow", "Zealous", "Aggressive", "Agile", "Agitated", "Agonizing", "Agreeable", "Ajar", "Alarmed", "Alarming", "Alert", "Alienated", "Alive", "All", "Altruistic", "Bland", "Blank", "Blaring", "Bleak", "Blind", "Blissful", "Blond", "Blue", "Blushing", "Cloudy", "Clueless", "Clumsy", "Cluttered", "Coarse", "Cold", "Colorful", "Colorless", "Colossal", "Comfortable", "Common", "Compassionate", "Competent", "Complete", "Delightful", "Demanding", "Dense", "Dental", "Dependable", "Dependent", "Descriptive", "Deserted", "Detailed", "Determined", "Devoted", "Different", "Embellished", "Eminent", "Emotional", "Empty", "Enchanted", "Enchanting", "Energetic", "Enlightened", "Enormous", "Fine", "Finished", "Firm", "First", "Firsthand", "Fitting", "Fixed", "Flaky", "Flamboyant", "Flashy", "Flat", "Flawless", "Flickering", "Gloomy", "Glorious", "Glossy", "Glum", "Golden", "Good", "Goodnatured", "Gorgeous", "Graceful", "Healthy", "Heartfelt", "Hearty", "Heavenly", "Heavy", "Hefty", "Helpful", "Humongous", "Impartial", "Impeccable", "Imperfect", "Imperturbable", "Important", "Impossible", "Impractical", "Impressionable", "Impressive", "Improbable", "Joint", "Jolly", "Jovial", "Juvenile", "Kindhearted", "Kindly", "Lighthearted", "Likable", "Likely", "Limited", "Limp", "Limping", "Linear", "Lined", "Liquid", "Medium", "Meek", "Mellow", "Melodic", "Memorable", "Menacing", "Merry", "Messy", "Metallic", "Mild", "Negative", "Neglected", "Negligible", "Neighboring", "Nervous", "New", "Oldfashioned", "Only", "Open", "Optimal", "Optimistic", "Opulent", "Plaintive", "Plastic", "Playful", "Pleasant", "Pleased", "Pleasing", "Plump", "Plush", "Pointed", "Pointless", "Poised", "Polished", "Polite", "Political", "Pungent", "Queasy", "Querulous", "Reliable", "Relieved", "Remarkable", "Remorseful", "Remote", "Repentant", "Required", "Respectful", "Responsible", "Silly", "Silver", "Similar", "Simple", "Simplistic", "Sizzling", "Skeletal", "Skinny", "Sleepy", "Slight", "Slim", "Slimy", "Slippery", "Slow", "Slushy", "Small", "Smart", "Smoggy", "Smooth", "Smug", "Snappy", "Snarling", "Sneaky", "Sniveling", "Snoopy", "Thick", "Thin", "Third", "Thirsty", "This", "Thorny", "Thorough", "Those", "Thoughtful", "Threadbare", "United", "Unkempt", "Unknown", "Unlined", "Unnatural", "Unrealistic", "Venerated", "Vengeful", "Verifiable", "Vibrant", "Vicious", "Wellgroomed", "Wellinformed", "Welllit", "Wellmade", "Welloff", "Welltodo", "Wellworn", "Wet", "Which", "Whimsical", "Whirlwind", "Whispered", "Worse", "Writhing", "Yellowish", "Zesty", "Amazing", "Ambitious", "Ample", "Amused", "Amusing", "Anchored", "Ancient", "Angelic", "Angry", "Anguished", "Animated", "Annual", "Another", "Antique", "Bogus", "Boiling", "Bold", "Bony", "Boring", "Bossy", "Both", "Bouncy", "Bountiful", "Bowed", "Complex", "Complicated", "Composed", "Concerned", "Concrete", "Confused", "Conscious", "Considerate", "Constant", "Content", "Conventional", "Cooked", "Cool", "Cooperative", "Difficult", "Digital", "Diligent", "Dim", "Dimpled", "Dimwitted", "Direct", "Discrete", "Entire", "Envious", "Equal", "Equatorial", "Essential", "Esteemed", "Ethical", "Euphoric", "Flimsy", "Flippant", "Flowery", "Fluffy", "Fluid", "Flustered", "Focused", "Fond", "Foolhardy", "Foolish", "Forceful", "Forked", "Formal", "Forsaken", "Gracious", "Grand", "Grandiose", "Granular", "Grateful", "Grave", "Gray", "Great", "Greedy", "Green", "Hidden", "High", "Highlevel", "Hilarious", "Hoarse", "Hollow", "Homely", "Inborn", "Incomparable", "Incompatible", "Incomplete", "Inconsequential", "Incredible", "Indelible", "Indolent", "Inexperienced", "Infamous", "Infantile", "Joyful", "Joyous", "Jubilant", "Klutzy", "Knobby", "Little", "Live", "Lively", "Livid", "Lone", "Long", "Milky", "Mindless", "Miniature", "Minor", "Minty", "Misguided", "Misty", "Mixed", "Next", "Nice", "Nifty", "Nimble", "Nippy", "Orange", "Orderly", "Ordinary", "Organic", "Ornate", "Ornery", "Poor", "Popular", "Portly", "Posh", "Positive", "Possible", "Potable", "Powerful", "Powerless", "Practical", "Precious", "Present", "Prestigious", "Questionable", "Quick", "Revolving", "Rewarding", "Rich", "Right", "Rigid", "Ringed", "Ripe", "Sociable", "Soft", "Soggy", "Solid", "Somber", "Some", "Sophisticated", "Sore", "Sorrowful", "Soulful", "Soupy", "Sour", "Spanish", "Sparkling", "Sparse", "Specific", "Spectacular", "Speedy", "Spherical", "Spicy", "Spiffy", "Spirited", "Spiteful", "Splendid", "Spotless", "Spotted", "Spry", "Thrifty", "Thunderous", "Tidy", "Tight", "Timely", "Tinted", "Tiny", "Tired", "Torn", "Total", "Unripe", "Unruly", "Unselfish", "Unsightly", "Unsteady", "Unsung", "Untidy", "Untimely", "Untried", "Victorious", "Vigilant", "Vigorous", "Villainous", "Violet", "Whole", "Whopping", "Wicked", "Wide", "Wideeyed", "Wiggly", "Wild", "Willing", "Wilted", "Winding", "Windy", "Young", "Zigzag", "Anxious", "Any", "Apprehensive", "Appropriate", "Apt", "Arctic", "Arid", "Aromatic", "Artistic", "Assured", "Astonishing", "Athletic", "Brave", "Breakable", "Brief", "Bright", "Brilliant", "Brisk", "Broken", "Bronze", "Brown", "Bruised", "Coordinated", "Corny", "Corrupt", "Costly", "Courageous", "Courteous", "Crafty", "Crazy", "Creamy", "Creative", "Creepy", "Crisp", "Dirty", "Disguised", "Distant", "Distant", "Distinct", "Distorted", "Dizzy", "Dopey", "Downright", "Dreary", "Even", "Evergreen", "Everlasting", "Every", "Evil", "Exalted", "Excellent", "Excitable", "Exemplary", "Exhausted", "Forthright", "Fortunate", "Fragrant", "Frail", "Frank", "Frayed", "Free", "French", "Frequent", "Fresh", "Friendly", "Frightened", "Frightening", "Gregarious", "Grim", "Grimy", "Gripping", "Grizzled", "Grouchy", "Grounded", "Honest", "Honorable", "Honored", "Hopeful", "Hospitable", "Hot", "Huge", "Infatuated", "Inferior", "Infinite", "Informal", "Innocent", "Insecure", "Insignificant", "Insistent", "Instructive", "Insubstantial", "Judicious", "Juicy", "Jumbo", "Knotty", "Knowing", "Knowledgeable", "Longterm", "Loose", "Lopsided", "Lost", "Loud", "Lovable", "Lovely", "Loving", "Modern", "Modest", "Moist", "Monthly", "Monumental", "Moral", "Mortified", "Motionless", "Nocturnal", "Noisy", "Nonstop", "Normal", "Notable", "Noted", "Original", "Other", "Our", "Outgoing", "Outlandish", "Outlying", "Precious", "Pretty", "Previous", "Pricey", "Prickly", "Primary", "Prime", "Pristine", "Private", "Prize", "Probable", "Productive", "Profitable", "Quickwitted", "Quiet", "Quintessential", "Roasted", "Robust", "Rosy", "Rotating", "Rotten", "Rough", "Round", "Rowdy", "Square", "Squeaky", "Squiggly", "Stable", "Staid", "Stained", "Stale", "Standard", "Starchy", "Stark", "Starry", "Steel", "Steep", "Sticky", "Stiff", "Stimulating", "Stingy", "Stormy", "Strange", "Strict", "Strident", "Striking", "Striped", "Strong", "Studious", "Stunning", "Tough", "Tragic", "Trained", "Treasured", "Tremendous", "Triangular", "Tricky", "Trifling", "Trim", "Untrue", "Unused", "Unusual", "Unwelcome", "Unwieldy", "Unwilling", "Unwitting", "Unwritten", "Upbeat", "Virtual", "Virtuous", "Visible", "Winged", "Wiry", "Wise", "Witty", "Wobbly", "Woeful", "Wonderful", "Wooden", "Woozy", "Wordy", "Worldly", "Worn", "Youthful", "Attached", "Attentive", "Attractive", "Austere", "Authentic", "Authorized", "Automatic", "Avaricious", "Average", "Aware", "Awesome", "Awful", "Awkward", "Bubbly", "Bulky", "Bumpy", "Buoyant", "Burdensome", "Burly", "Bustling", "Busy", "Buttery", "Buzzing", "Critical", "Crooked", "Crowded", "Crushing", "Cuddly", "Cultivated", "Cultured", "Cumbersome", "Curly", "Curvy", "Cute", "Cylindrical", "Doting", "Double", "Downright", "Drab", "Drafty", "Dramatic", "Dry", "Dual", "Dutiful", "Excited", "Exciting", "Exotic", "Expensive", "Experienced", "Expert", "Extralarge", "Extraneous", "Extrasmall", "Extroverted", "Frilly", "Frivolous", "Frizzy", "Front", "Frosty", "Frozen", "Frugal", "Fruitful", "Full", "Fumbling", "Functional", "Funny", "Fussy", "Fuzzy", "Growing", "Growling", "Grown", "Grubby", "Grumpy", "Guilty", "Gullible", "Gummy", "Humble", "Humming", "Hungry", "Husky", "Intelligent", "Intent", "Intentional", "Interesting", "Internal", "International", "Intrepid", "Ironclad", "Irresponsible", "Itchy", "Jumpy", "Junior", "Known", "Kooky", "Low", "Loyal", "Lucky", "Lumbering", "Luminous", "Lumpy", "Lustrous", "Luxurious", "Mountainous", "Muddy", "Muffled", "Mundane", "Murky", "Mushy", "Musty", "Mysterious", "Noteworthy", "Novel", "Noxious", "Numb", "Nutritious", "Nutty", "Outrageous", "Outstanding", "Oval", "Overcooked", "Overdue", "Overjoyed", "Profuse", "Proper", "Proud", "Prudent", "Punctual", "Puny", "Pure", "Purple", "Pushy", "Puzzled", "Puzzling", "Quirky", "Quixotic", "Quizzical", "Royal", "Rubbery", "Ruddy", "Rundown", "Runny", "Rural", "Rusty", "Stupendous", "Sturdy", "Stylish", "Subdued", "Substantial", "Subtle", "Suburban", "Sudden", "Sugary", "Sunny", "Super", "Superb", "Superficial", "Superior", "Supportive", "Surefooted", "Surprised", "Suspicious", "Svelte", "Sweaty", "Sweet", "Sweltering", "Swift", "Sympathetic", "Trivial", "Troubled", "Trusting", "Trustworthy", "Trusty", "Truthful", "Tubby", "Turbulent", "Twin", "Upright", "Upset", "Urban", "Usable", "Used", "Useful", "Useless", "Utilized", "Utter", "Vital", "Vivacious", "Vivid", "Voluminous", "Worst", "Worthwhile", "Worthy", "Wrathful", "Wry", "Yummy", "True", "Aliceblue", "Aqua", "Aquamarine", "Azure", "Beige", "Bisque", "Blanchedalmond", "Blue", "Blueviolet", "Brown", "Burlywood", "Cadetblue", "Chartreuse", "Chocolate", "Coral", "Cornflowerblue", "Cornsilk", "Crimson", "Cyan", "Darkblue", "Darkcyan", "Darkgoldenrod", "Darkgray", "Darkgreen", "Darkgrey", "Darkkhaki", "Darkmagenta", "Darkolivegreen", "Darkorange", "Darkorchid", "Darkred", "Darksalmon", "Darkseagreen", "Darkslateblue", "Darkslategray", "Darkslategrey", "Darkturquoise", "Darkviolet", "Deeppink", "Deepskyblue", "Dimgray", "Dimgrey", "Dodgerblue", "Firebrick", "Floralwhite", "Forestgreen", "Fractal", "Fuchsia", "Gainsboro", "Ghostwhite", "Gold", "Goldenrod", "Gray", "Green", "Greenyellow", "Honeydew", "Hotpink", "Indianred", "Indigo", "Ivory", "Khaki", "Lavender", "Lavenderblush", "Lawngreen", "Lemonchiffon", "Lightblue", "Lightcoral", "Lightcyan", "Lightgoldenrod", "Lightgoldenrodyellow", "Lightgray", "Lightgreen", "Lightgrey", "Lightpink", "Lightsalmon", "Lightseagreen", "Lightskyblue", "Lightslateblue", "Lightslategray", "Lightsteelblue", "Lightyellow", "Lime", "Limegreen", "Linen", "Magenta", "Maroon", "Mediumaquamarine", "Mediumblue", "Mediumforestgreen", "Mediumgoldenrod", "Mediumorchid", "Mediumpurple", "Mediumseagreen", "Mediumslateblue", "Mediumspringgreen", "Mediumturquoise", "Mediumvioletred", "Midnightblue", "Mintcream", "Mistyrose", "Moccasin", "Navajowhite", "Navy", "Navyblue", "Oldlace", "Olive", "Olivedrab", "Opaque", "Orange", "Orangered", "Orchid", "Palegoldenrod", "Palegreen", "Paleturquoise", "Palevioletred", "Papayawhip", "Peachpuff", "Peru", "Pink", "Plum", "Powderblue", "Purple", "Red", "Rosybrown", "Royalblue", "Saddlebrown", "Salmon", "Sandybrown", "Seagreen", "Seashell", "Sienna", "Silver", "Skyblue", "Slateblue", "Slategray", "Slategrey", "Snow", "Springgreen", "Steelblue", "Tan", "Teal", "Thistle", "Tomato", "Transparent", "Turquoise", "Violet", "Violetred", "Wheat", "Whitesmoke", "Yellow", "Yellowgreen"]

    @staticmethod
    def generate_username(num_words=2, separator='-'):
        """Generate a new username."""
        max_iterations = 100
        for i in range(max_iterations):
            words = []
            words.append(random.choice(User.adjectives).lower())
            words.append(random.choice(User.animals).lower())
            username = separator.join(words)
            if User.objects.filter(username=username).exists() is False:
                return username
        return False

    @staticmethod
    def get_default_email(username):
        """Return the user's system-generated email."""
        return User.DEFAULT_EMAIL_FORMAT.format(username)

    @property
    def full_name(self):
        """Get full name."""
        names = []
        if self.first_name is not None:
            names.append(self.first_name)
        if self.last_name is not None:
            names.append(self.last_name)
        name = ''
        if len(names) > 0:
            name = " ".join(names)
        return name

    def create_password_request(self):
        """Create a new password request."""
        password_reset_token = PasswordResetRequest()
        password_reset_token.user = self
        password_reset_token.save()
        return password_reset_token

    def login(self, request):
        """Log in user."""
        return login(request, self, backend=settings.DEFAULT_AUTHENTICATION_BACKEND)

    def logout(self, request):
        """Log out user."""
        return logout(request)  # , backend=settings.DEFAULT_AUTHENTICATION_BACKEND)

    def confirm_account(self):
        """Confirm account."""
        self.is_confirmed = True
        self.generate_backup_wallet_password(commit=False)
        self.save()

    def set_backup_wallet_password_seen(self):
        """Confirm account."""
        self.is_backup_wallet_password_seen = True
        self.save()

    def generate_random_string(self, length):
        """Generate a confirmation code."""
        alphabet = string.digits + string.ascii_lowercase + string.ascii_uppercase
        return ''.join(random.choice(alphabet) for i in range(length))

    def generate_confirmation_code(self, commit=True):
        """Generate a confirmation code."""
        token_length = 64
        self.confirmation_code = self.generate_random_string(token_length)
        if commit is True:
            self.save()

    def generate_password_recovery_token(self, commit=True):
        """Generate a confirmation code."""
        token_length = 64
        self.password_recovery_token = self.generate_random_string(token_length)
        if commit is True:
            self.save()

    def generate_backup_wallet_password(self, commit=True):
        """Generate a confirmation code."""
        token_length = 64
        self.backup_wallet_password = self.generate_random_string(token_length)
        if commit is True:
            self.save()

    def get_account_confirmation_status_url(self, request):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common_api_0_3_account_management:check_account_registration_confirmation', kwargs={'username': self.username}))

    def get_account_confirmation_url(self, request):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common:confirm_account_registration_with_confirm_code', kwargs={'username': self.username, 'confirmation_code': self.confirmation_code}))

    def send_account_registration_confirmation_email(self, request, template_set_name='common/emails/customer__create_account_confirmation', fail_silently=False):
        """Send an email to the user confirming their password reset request."""
        if self.confirmation_code is None:
            self.generate_confirmation_code(commit=True)

        context = {
            'user': self,
            'account_confirmation_url': self.get_account_confirmation_url(request)
        }
        account_confirm_email = HtmlEmail(
            template_set_name,
            settings.DEFAULT_FROM_EMAIL,
            [self.email],
            context
        )
        account_confirm_email.send(fail_silently)

    @classmethod
    def pre_save(cls, instance, *args, **kwargs):
        """Pre-save script. Generate public/private key."""
        if instance.public_key_id is None and instance.public_key is not None:
            instance.public_key_id = "{}-{}".format(instance.public_key[:10], instance.id)
        if instance.is_confirmed is True and instance.backup_wallet_password is None:
            instance.generate_backup_wallet_password(commit=False)
        if instance.password_recovery_token is None:
            instance.generate_password_recovery_token(commit=False)


pre_save.connect(User.pre_save, sender=User)


class PublicKey(models.Model):
    """Public keys."""

    public_key_id = models.CharField(max_length=32, null=True, blank=True)
    public_key = models.TextField(max_length=500)
    algorithm = models.CharField(max_length=32, default='rsa-sha256')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Represent as string."""
        return str(self.public_key)

    @classmethod
    def post_save(cls, sender, instance, created, **kwargs):
        """Sent when post_save signal is sent."""
        if instance is not None:
            if instance.public_key_id is None or instance.public_key_id == '':
                instance.public_key_id = "{}-{}-{}".format(instance.algorithm, instance.public_key[27:37], instance.id)
                instance.save()


post_save.connect(PublicKey.post_save, sender=PublicKey)


class PasswordResetRequest(models.Model):
    """Password reset token. Created when a user requests to reset their password."""

    EXPIRES_HOURS = 1

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password_reset_token = models.CharField(max_length=120, null=True, blank=True)
    expires_on = models.DateTimeField(null=True, blank=True)
    is_complete = models.BooleanField(default=False)
    is_seen = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    password_reset_status_url = None

    def __str__(self):
        """Represent as string."""
        return self.password_reset_token

    def confirm(self):
        """Set is_complete to True and save."""
        self.is_complete = True
        self.save()

    def get_password_reset_status_url(self, request, email_or_username):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common_api_0_3_account_management:password_reset', kwargs={'email_or_username': email_or_username}))

    def get_password_reset_confirmation_url(self, request):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common:confirm_reset_password_request_with_token', kwargs={'username': self.user.username, 'password_reset_token': self.password_reset_token}))
    '''
    def get_password_reset_status_url_with_token(self, request):
        """Return the reset password confirmation status API endpoint."""
        return request.build_absolute_uri(reverse('common_api_0_3_account_management:password_reset', kwargs={'password_recovery_token': self.user.password_recovery_token}))
    '''
    def generate_token(self):
        """Generate a token."""
        token_length = 64
        alphabet = string.digits + string.ascii_lowercase
        self.password_reset_token = ''.join(random.choice(alphabet) for i in range(token_length))

    def send_password_reset_confirmation_email(self, request, email_or_username, template_set_name='common/emails/customer__reset_password_request', fail_silently=False):
        """Send an email to the user confirming their password reset request."""
        if self.password_reset_token is None:
            self.generate_token()

        context = {
            'password_reset_token': self,
            'user': self.user,
            'password_reset_confirmation_url': self.get_password_reset_confirmation_url(request)
        }
        password_reset_email = HtmlEmail(
            template_set_name,
            settings.DEFAULT_FROM_EMAIL,
            [self.user.email],
            context
        )
        password_reset_email.send(fail_silently)

    @classmethod
    def pre_save(cls, instance, *args, **kwargs):
        """Pre-save script. Generate public/private key."""
        if instance.password_reset_token is None:
            instance.generate_token()
        if instance.expires_on is None:
            instance.expires_on = timezone.now() + timezone.timedelta(hours=instance.EXPIRES_HOURS)


pre_save.connect(PasswordResetRequest.pre_save, sender=PasswordResetRequest)


class HtmlEmail:
    """EmailMultiAlternative wrapper."""

    # This code is open source, created by backupbrain@gmail.com

    email_multi_alternative = None
    template_set_name = None
    text_template = None
    html_template = None
    subject_template = None

    def __init__(self, template_set_name, from_email, to_emails, context, reply_to=None, headers=None):
        """Initialize the email."""
        subject_template_file = "{}_subject.txt".format(template_set_name)
        subject_template = render_to_string(subject_template_file, context)
        text_template_file = "{}.txt".format(template_set_name)
        text_template = None

        try:
            text_template = render_to_string(text_template_file, context)
        except Exception:
            print("problem creating text template")
            traceback.print_exc()
        html_template_file = "{}.html".format(template_set_name)
        html_template = None
        try:
            html_template = render_to_string(html_template_file, context)
        except Exception:
            print("problem creating html template")
            traceback.print_exc()
            pass
        self.email_multi_alternative = EmailMultiAlternatives(
            subject_template,
            text_template,
            from_email,
            to_emails,
            reply_to=reply_to,
            headers=headers
        )
        if html_template is not None and html_template != '':
            self.email_multi_alternative.attach_alternative(html_template, "text/html")
            if text_template is None:
                self.email_multi_alternative.content_subtype = 'html'
        if text_template is None and (html_template is None or html_template == ''):
            raise Exception('No templates found')

    def attach(self, attachment_name, file_data, mime_type):
        """Attach a file."""
        self.email_multi_alternative.attach(attachment_name, file_data, mime_type)

    def attach_file(self, path):
        """Attach a file."""
        self.email_multi_alternative.attach_file(path)

    def send(self, fail_silently=False):
        """Send email."""
        self.email_multi_alternative.send(fail_silently)
