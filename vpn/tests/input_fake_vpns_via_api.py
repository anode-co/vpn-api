#!/usr/bin/env python3
import json
import requests
import string
import random

vpn_names = [
    # "Bark Twain",
    # "Chewbarka",
    # "Doc McDoggins",
    "Droolius Caesar",
    "Franz Fur-dinand",
    "Fyodor Dogstoevsky",
    "Hairy Paw-ter",
    "Jimmy Chew",
    "Kareem Abdul Ja-Bark",
    "Mary Puppins",
    "The Notorious D.O.G.",
    "Orville Redenbarker",
    "Ozzy Pawsborne",
    "Prince of Barkness",
    "Salvador Dogi",
    "Santa Paws",
    "Sarah Jessica Barker",
    "Sherlock Bones",
    "Winnie the Poodle",
    "Woofgang Puck",
    "Bing Clawsby",
    "Brad Kitt",
    "Bob Meowerly",
    "Butch Catsidy",
    "The Great Catsby",
    "William Shakespaw",
    "Lucifurr",
    "Fuzz Aldrin",
    "Anderson Pooper",
    "Cat Damon",
    "Cat Sajak",
    "Catsanova",
    "Picatso",
    "Notorious C.A.T",
    "Cat Stevens",
    "Genghis Cat",
    "David Meowie",
    "Meowses",
    "Catrick Swayze",
    "Walter Croncat",
    "Chairman Meow",
    "Dalai Clawma",
    "Elvis Catsley",
    "Bob Scratchit",
    "Paw Revere",
    "Purr-nest Hemingway",
    "Fidel Catstro",
    "Catpernicus",
    "Hairy Potter",
    "Jean Luc Picat",
    "Jude Paw",
    "Mr. Meowgi",
    "Oedipuss",
    "Santa Claws",
    "Luke Skywhisker",
    "Cat-man-do",
    "Jerry Flea Lewis",
    "Cat Cobain",
    "Fidel Catstro",
    "Paul McCatney",
    "Charles Lickens",
    "Henry Hissinger",
    "Tom Pawyer",
    "Colin Feral Cat",
    "Jaspurr",
    "Cat Benatar",
    "Catsy Cline",
    "Fur-gie",
    "Chairwoman Miao",
    "Ali Cat",
    "Empurress",
    "Cat Middleton",
    "Clawdia",
    "Jennifurr",
    "Jennipurr",
    "Jessicat",
    "Cat-trina",
    "Katy Purry",
    "Cleo-cat-ra",
    "Fleas Witherspoon",
    "Ali McClaw",
    "Puma Thurman",
    "Angelicat",
    "Tabbytha",
    "Catalie Portman",
    "Cindy Clawford",
    "Veronicat",
    "Pawdrey Hepburn",
    "Demi Meower",
    "Halley Purry",
    "Hello Kitty",
    "Kitty Poppins",
    "Jane Pawsten",
    "Meowly Cyrus",
    "Whispurr",
    "Catzilla",
    "Miss Thing",
    "She-ra",
    "JK Meowling",
    "Catnip Everclean",
    "Margaret Scratcher",
    "Copy Cat",
    "Americat",
    "Cameow",
    "Puddy Tat",
    "Purrson",
    "Catapult",
    "Catsup",
    "Kit Cat",
    "Catastrophe",
    "Catillac",
    "Fuzzinator",
    "Meowsical",
    "Purrfect",
    "Domesticat",
    "Gigabyte",
    "Cat-titude",
    "Clawsome",
    "Clawsy",
    "Galacticat",
    "Octopuss",
    "Miraclaw",
    "Catillac",
    "Boss Cat",
    "Whisker",
    "Bubble-O-Seven",
    "Catabunga",
    "Catagonia",
    "Caterpillar",
    "Catserole",
    "Felinear",
    "Itchy",
    "Puss ‘n Boots",
    "Thundercat",
    "Ravenclaw",
]

login_names = [
    'in_jail_out_soon',
    'desperate_enuf',
    'herpes_free_since_03',
    'kiss-my-axe',
    'king_0f_dairy_queen',
    'dildo_swaggins',
    'shaquille_oatmeal',
    'ask_yo_girl_about_me',
    'hanging_with_my_gnomies',
    'big_mamas_house',
    'hugs_for_drugs',
    'bill_nye_the_russian_spy',
    'hoosier_daddy',
    'intelligent_zombie',
    'hugo_balls',
    'stinky_pinky',
    'fast_and_the_curious',
    'bad_karma',
    'tea_baggins',
    'average_student',
    'protect_ya_neck',
    'sloppy_wet',
    'matthew_high_damage',
    'imma_rage_quit',
    'xbox_sign_out',
    'magic_fetus',
    'butt_smasher',
    'mama_karma',
    'google_was_my_idea',
    'i_was_a_mistake',
    'sold_mom_for_rp',
    'dusty_bawls',
    'zero_deaths',
    'better_than_you',
    'do_not_leave_me',
    'date_me',
    'uncommon_name',
    'name_not_important',
    'image_not_uploaded',
    'i_boop_ur_nose',
    'unfriend_now',
    'im_watching_you',
    'whos_ur_buddha',
    'cute_as_ducks',
    'prince_charming',
    'godfather_part_4',
    'oprah_wind_fury',
    'google_me_now',
    'thot_patrol',
    'suck_my_popsicle',
    'my_name_is_in_use',
    'pig_benis',
    'i_love_my_mommy',
    'period_blood',
    'heisenberg_blue',
    'ben_dover',
    'ass_ass_in',
    'i_killed_cupid',
    'ben_aflek_is_an_ok_actor',
    'fresh_out_the_oven',
    'monkey_see',
    'hello_im_creepy',
    'cowabunga_dude',
    'dangerous_with_rocks',
    'raised_by_wolves',
    'an_innocent_child',
    'sofa_king_cool',
    'oliver_clothes_off',
    'take_your_pants_off',
    'cereal_killer',
    'strike_u_r_out',
    'behind_you',
    'my_name_is',
    'been_there_done_that',
    'no_child_support',
    'black_knight',
    'sleeping_beauty',
    'who_am_i',
    'hakuna_matata',
    'how_you_doing',
    'mother_of_dragons',
    'epic_fail',
    'tin_foil_hat',
    'yes_u_suck',
    'casanova',
    'say_my_name',
    'sinking_swimmer',
    'banana_hammock',
    'crazy_cat_lady',
    'me_for_president',
    'cowgirl_up',
    'real_name_hidden',
    'anonymouse',
    'not_james_bond',
    'itchy_and_scratchy',
    'dumbest_man_alive',
    'bros_before_hoes',
    'laugh_till_u_pee',
    'hairy_poppins',
    'rambo_was_real',
    'regina_phalange',
    'fedora_the_explorer',
    'i_can_see_your_pixels',
    'unfinished_sentenc',
    'a_collection_of_cells',
    'OP_rah',
    'well_endowed',
    'my_anaconda_does',
    'hey_you',
    'pluralizes_everythings',
    'test_name_please_ignore',
]


class FakeVpnServer:
    """A fake vpn server."""

    COUNTRY_CODES = ['AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BY', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BQ', 'BA', 'BW', 'BV', 'BR', 'IO', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'KY', 'CF', 'TD', 'CL', 'CN', 'CX', 'CC', 'CO', 'KM', 'CD', 'CG', 'CK', 'CR', 'CI', 'HR', 'CU', 'CW', 'CY', 'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GF', 'PF', 'TF', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GP', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'VA', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IR', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'KP', 'KR', 'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MO', 'MK', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT', 'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MS', 'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN', 'LC', 'MF', 'PM', 'VC', 'WS', 'SM', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SX', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'SS', 'ES', 'LK', 'SD', 'SR', 'SJ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'UM', 'US', 'UY', 'UZ', 'VU', 'VE', 'VN', 'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW']
    US_STATES = ['Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado', 'Connecticut', 'Delaware', 'District of Columbia', 'Florida', 'Georgia', 'Hawaii', 'Idaho', 'Illinois', 'Indiana', 'Iowa', 'Kansas', 'Kentucky', 'Louisiana', 'Maine', 'Maryland', 'Massachusetts', 'Michigan', 'Minnesota', 'Mississippi', 'Missouri', 'Montana', 'Nebraska', 'Nevada', 'New Hampshire', 'New Jersey', 'New Mexico', 'New York', 'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon', 'Pennsylvania', 'Rhode Island', 'South Carolina', 'South Dakota', 'Tennessee', 'Texas', 'Utah', 'Vermont', 'Virginia', 'Washington', 'West Virginia', 'Wisconsin', 'Wyoming', 'American Samoa', 'Guam', 'Northern Mariana Islands', 'Puerto Rico', 'U.S. Virgin Islands']
    MX_STATES = ['Aguascalientes', 'Baja California', 'Baja California Sur', 'Campeche', 'Chiapas', 'Chihuahua', 'Coahuila', 'Colima', 'Mexico City', 'Durango', 'Guanajuato', 'Guerrero', 'Hidalgo', 'Jalisco', 'México', 'Michoacán', 'Morelos', 'Nayarit', 'Nuevo León', 'Oaxaca', 'Puebla', 'Querétaro', 'Quintana Roo', 'San Luis Potosí', 'Sinaloa', 'Sonora', 'Tabasco', 'Tamaulipas', 'Tlaxcala', 'Veracruz', 'Yucatán', 'Zacatecas']
    CA_PROVINCES = ['Ontario', 'Quebec', 'Nova Scotia', 'New Brunswick', 'Manitoba', 'British Columbia', 'Prince Edward Island', 'Saskatchewan', 'Alberta', 'Newfoundland and Labrador']
    AU_PROVINCES = ['Australian Capital Territory', 'New South Wales', 'Victoria', 'Queensland', 'South Australia', 'Western Australia', 'Tasmania', 'Northern Territory', 'External territories', 'Norfolk Island', 'Christmas Island', 'Cocos Island', 'Australian Antarctic Territory']

    def __init__(self, name):
        """Initialize."""
        self.name = name
        self.public_key = self.generate_public_key()
        self.bandwidth_bps = self.generate_bandwidth_bps()
        self.country_code = self.get_country_code()
        self.region = self.get_region()
        self.network_settings = self.get_network_settings()

    def to_json(self):
        """Output as JSON."""
        output = {
            'name': self.name,
            'public_key': self.public_key,
            'bandwidth_bps': self.bandwidth_bps,
            'country_code': self.country_code,
            'region': self.region,
            'network_settings': self.network_settings
        }
        return output

    def generate_public_key(self):
        """Generate a public key."""
        length = 52
        options = string.ascii_lowercase + string.digits
        public_key = ''.join(random.choice(options) for i in range(length))
        return '{}.k'.format(public_key)

    def generate_bandwidth_bps(self):
        """Generate a random bandwidth."""
        speeds = [
            100 * 1024 * 1024 * 1024,
            1000 * 1024 * 1024 * 1024,
            100000 * 1024 * 1024 * 1024
        ]
        return random.choice(speeds)

    def get_country_code(self):
        """Generate a random country code."""
        return random.choice(self.COUNTRY_CODES)

    def get_region(self):
        """Generate a random region code."""
        if self.country_code == "US":
            return random.choice(self.US_STATES)
        elif self.country_code == 'MX':
            return random.choice(self.MX_STATES)
        elif self.country_code == 'AU':
            return random.choice(self.AU_PROVINCES)
        elif self.country_code == 'CA':
            return random.choice(self.CA_PROVINCES)
        return None

    def get_weighted_count(self, min_value, max_value):
        """Get a weighted count of something."""
        possibilities = []
        probabilities = []
        counter = 1
        for i in range(min_value, max_value + 1):
            possibilities.append(i)
            probabilities.append(
                0.5 / counter
            )
            counter += 1
        result = random.choices(
            population=possibilities,
            weights=probabilities,
            k=1
        )[0]
        return result

    def get_ip_range(self):
        """Get an IP range."""
        is_ipv6 = random.choice([True, False])
        if is_ipv6 is True:
            m = 16**4
            output = {
                'min': "2001:cafe:" + ":".join(("%x" % random.randint(0, m) for i in range(6))),
                'max': "2001:cafe:" + ":".join(("%x" % random.randint(0, m) for i in range(6)))
            }
        else:
            prefix = "{}.{}.{}".format(
                random.randint(1, 254),
                random.randint(0, 254),
                random.randint(0, 254),
            )
            range_min = random.randint(1, 253)
            range_max = random.randint(range_min, 254)
            output = {
                'min': "{}.{}".format(prefix, range_min),
                'max': "{}.{}".format(prefix, range_max)
            }
        return output

    def get_peering_line(self):
        """Create a random peering line."""
        peering_line = {
            'name': random.choice(login_names),
            'login': random.choice(login_names),
            'password': self.generate_public_key()
        }
        return peering_line

    def get_network_settings(self):
        """Create some network settings."""
        network_settings = {}
        network_settings['uses_nat'] = random.choice([True, False])
        network_settings['peer_client_allocation_size'] = '/{}'.format(random.randint(0, 255))
        network_settings['nat_exit_ranges'] = []
        network_settings['client_allocation_ranges'] = []
        network_settings['peering_lines'] = []
        num_allocation_ranges = self.get_weighted_count(1, 5)
        for i in range(1, num_allocation_ranges + 1):
            ip_range = self.get_ip_range()
            network_settings['client_allocation_ranges'].append(ip_range)
        if network_settings['uses_nat'] is True:
            num_exit_ranges = self.get_weighted_count(1, 5)
            for i in range(1, num_exit_ranges):
                ip_range = self.get_ip_range()
                network_settings['nat_exit_ranges'].append(ip_range)
        num_peering_lines = self.get_weighted_count(0, 5)
        for i in range(0, num_peering_lines):
            network_settings['peering_lines'].append(self.get_peering_line())
        return network_settings


def main():
    """Generate fake vpns."""
    vpns = []
    for name in vpn_names:
        print("making {}".format(name))
        vpn = FakeVpnServer(name)
        vpns.append(vpn)
        json_vpn = vpn.to_json()
        result = requests.post('https://vpn.anode.co/api/0.2/vpn/servers/', json=json_vpn)
        print(result.status_code)
        print(result.text)
    # print(json.dumps(vpn.to_json(), indent=4))


if __name__ == '__main__':
    main()
