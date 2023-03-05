#include "kernel_ctx/kernel_ctx.h"
#include "drv_image/drv_image.h"
#include "raw_driver.hpp"
#include "auth.hpp"
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;

std::string name = skCrypt("").decrypt(); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = skCrypt("").decrypt(); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = skCrypt("").decrypt(); // app secret, the blurred text on licenses tab and other tabs
std::string version = skCrypt("1.0").decrypt(); // leave alone unless you've changed version on website
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting

/*
	Video on what ownerid and secret are https://youtu.be/uJ0Umy_C6Fg

	Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA

	Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version, url);

int __cdecl main(int argc, char** argv)
{
	std::string consoleTitle = (std::string)skCrypt("Loader - Built at:  ") + compilation_date + " " + compilation_time;
	SetConsoleTitleA(consoleTitle.c_str());
	std::cout << skCrypt("\n\n Connecting..");
	KeyAuthApp.init();
	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	/*
		Optional - check if HWID or IP blacklisted

	if (KeyAuthApp.checkblack()) {
		abort();
	}
	*/

	std::cout << skCrypt("\n\n App data:");
	std::cout << skCrypt("\n Number of users: ") << KeyAuthApp.data.numUsers;
	std::cout << skCrypt("\n Number of online users: ") << KeyAuthApp.data.numOnlineUsers;
	std::cout << skCrypt("\n Number of keys: ") << KeyAuthApp.data.numKeys;
	std::cout << skCrypt("\n Application Version: ") << KeyAuthApp.data.version;
	std::cout << skCrypt("\n Customer panel link: ") << KeyAuthApp.data.customerPanelLink;
	std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
	KeyAuthApp.check();
	std::cout << skCrypt("\n Current Session Validation Status: ") << KeyAuthApp.data.message;
	if (argc < 2)
	{
		std::perror("[-] invalid use, please provide a path to a driver\n");
		return -1;
	}
	std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

	int option;
	std::string username;
	std::string password;
	std::string key;

	std::cin >> option;
	switch (option)
	{
	case 1:
		std::cout << skCrypt("\n\n Enter username: ");
		std::cin >> username;
		std::cout << skCrypt("\n Enter password: ");
		std::cin >> password;
		KeyAuthApp.login(username, password);
		break;
	case 2:
		std::cout << skCrypt("\n\n Enter username: ");
		std::cin >> username;
		std::cout << skCrypt("\n Enter password: ");
		std::cin >> password;
		std::cout << skCrypt("\n Enter license: ");
		std::cin >> key;
		KeyAuthApp.regstr(username, password, key);
		break;
	case 3:
		std::cout << skCrypt("\n\n Enter username: ");
		std::cin >> username;
		std::cout << skCrypt("\n Enter license: ");
		std::cin >> key;
		KeyAuthApp.upgrade(username, key);
		break;
	case 4:
		std::cout << skCrypt("\n Enter license: ");
		std::cin >> key;
		KeyAuthApp.license(key);
		break;
	default:
		std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
		Sleep(3000);
		exit(0);
	}
	std::cout << skCrypt("\n User data:");
	std::cout << skCrypt("\n Username: ") << KeyAuthApp.data.username;
	std::cout << skCrypt("\n IP address: ") << KeyAuthApp.data.ip;
	std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.data.hwid;
	std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.createdate)));
	std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.lastlogin)));
	std::cout << skCrypt("\n Subscription(s): ");

	for (int i = 0; i < KeyAuthApp.data.subscriptions.size(); i++) { // Prompto#7895 was here
		auto sub = KeyAuthApp.data.subscriptions.at(i);
		std::cout << skCrypt("\n name: ") << sub.name;
		std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
	}

	std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
	KeyAuthApp.check();
	std::cout << skCrypt("\n Current Session Validation Status: ") << KeyAuthApp.data.message;

	std::vector<std::uint8_t> drv_buffer;
	util::open_binary_file(argv[1], drv_buffer);
	if (!drv_buffer.size())
	{
		std::perror("[-] invalid drv_buffer size\n");
		return -1;
	}

	physmeme::drv_image image(drv_buffer);
	if (!physmeme::load_drv())
	{
		std::perror("[!] unable to load driver....\n");
		return -1;
	}

	physmeme::kernel_ctx kernel_ctx;
	std::printf("[+] driver has been loaded...\n");
	std::printf("[+] %s mapped physical page -> 0x%p\n", physmeme::syscall_hook.first, physmeme::psyscall_func.load());
	std::printf("[+] %s page offset -> 0x%x\n", physmeme::syscall_hook.first, physmeme::nt_page_offset);
	const auto drv_timestamp = util::get_file_header((void*)raw_driver)->TimeDateStamp;
	if (!kernel_ctx.clear_piddb_cache(physmeme::drv_key, drv_timestamp))
	{
		// this is because the signature might be broken on these versions of windows.
		perror("[-] failed to clear PiDDBCacheTable.\n");
		return -1;
	}
	const auto _get_export_name = [&](const char* base, const char* name)
	{
		return reinterpret_cast<std::uintptr_t>(util::get_kernel_export(base, name));
	};

	image.fix_imports(_get_export_name);
	image.map();

	const auto pool_base = kernel_ctx.allocate_pool(image.size(), NonPagedPool);
	image.relocate(pool_base);
	kernel_ctx.write_kernel(pool_base, image.data(), image.size());
	auto entry_point = reinterpret_cast<std::uintptr_t>(pool_base) + image.entry_point();

	auto result = kernel_ctx.syscall<DRIVER_INITIALIZE>
	(
		reinterpret_cast<void*>(entry_point),
		reinterpret_cast<std::uintptr_t>(pool_base),
		image.size()
	);
	std::printf("[+] driver entry returned: 0x%p\n", result);
	system("pause");
	kernel_ctx.zero_kernel_memory(pool_base, image.header_size());
	if (!physmeme::unload_drv())
	{
		std::perror("[!] unable to unload driver... all handles closed?\n");
		return -1;
	}

	std::printf("[=] press enter to close\n");
	std::cin.get();
}
std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}