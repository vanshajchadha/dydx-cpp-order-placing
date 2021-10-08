#include <iostream>
#include <string>
#include <unordered_map>
#include <ctime>
#include <stdlib.h>
#include <algorithm>
#include <iomanip>
#include <math.h>
#include <sstream>
#include <curl/curl.h>
#include "boost/multiprecision/cpp_int.hpp"
#include <openssl/hmac.h>
#include "starkware/crypto/ffi/ecdsa.cc"
#include "starkware/crypto/ffi/pedersen_hash.cc"
#include "hmac.h"
#include "sha256.h"
#include "base64.h"
#include "json.hpp"

using namespace std;
using namespace boost::multiprecision;
using json = nlohmann::json;

class RequestHelper{

	public:
		RequestHelper(){
			base64_url_alphabet = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
			};
		}

		json request(const string& uri, const string& method, const json& headers, const json& data){
		    auto response = send_post_request(
		        uri,
		        headers,
		        json2string(data)
		    );
	
		    return response;
		}
		
		static int debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr){
			cout << data << endl;
			return 0;
		}
 
		json send_post_request(const string& uri, const json& headers, const string& data){
			CURL *curl_handle;
  			CURLcode result;

  			curl_global_init(CURL_GLOBAL_DEFAULT);

  			curl_handle = curl_easy_init();
  			cout << "Curl Request Initialized" << endl;

  			struct curl_slist *htttpheaders = NULL;
		    htttpheaders = curl_slist_append(htttpheaders, "Accept: application/json");
		    htttpheaders = curl_slist_append(htttpheaders, "Content-Type: application/json");
		    htttpheaders = curl_slist_append(htttpheaders, "charset: utf-8");
		    htttpheaders = curl_slist_append(htttpheaders, ("DYDX-SIGNATURE: " + headers["DYDX-SIGNATURE"].get<string>()).c_str());
		    htttpheaders = curl_slist_append(htttpheaders, ("DYDX-API-KEY: " + headers["DYDX-API-KEY"].get<string>()).c_str());
		    htttpheaders = curl_slist_append(htttpheaders, ("DYDX-TIMESTAMP: " + headers["DYDX-TIMESTAMP"].get<string>()).c_str());
		    htttpheaders = curl_slist_append(htttpheaders, ("DYDX-PASSPHRASE: " + headers["DYDX-PASSPHRASE"].get<string>()).c_str());

  			if(curl_handle) {
  				curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, htttpheaders);
			    curl_easy_setopt(curl_handle, CURLOPT_URL, uri.c_str());
			    curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
			    curl_easy_setopt(curl_handle, CURLOPT_COPYPOSTFIELDS, data.c_str());

			    // Enable in case of request debugging
			    /*curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, debug_callback);
			    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);*/

			    cout << "Curl Request Sending..." << endl;
			    result = curl_easy_perform(curl_handle);
			    cout << "Curl Request Sent" << endl;

			    if(result != CURLE_OK) {
		      		fprintf(stderr, "error: %s\n", curl_easy_strerror(result));
			    } 
			    else {
			    	cout << result << endl;
			    }
			    cout << "Curl Request Ended" << endl;
			    curl_easy_cleanup(curl_handle);
		  	}

		  	curl_global_cleanup();

		    return {};
		}

		string generate_now_iso(){
			time_t lt = time(0);
			auto local_field = *gmtime(&lt);
		    char buf[30];
		    strftime(buf, sizeof(buf), "%FT%TZ\n", &local_field);
		    std::cout << buf;
		    return buf;
		}

		string json2string(const json& root){
			const string json_string = root.dump();
		    return json_string;
		}

		string base64_url_encode(const string & in) {
			string out;
			int val =0, valb=-6;
			size_t len = in.length();
			unsigned int i = 0;
			for (i = 0; i < len; i++) {
			unsigned char c = in[i];
			val = (val<<8) + c;
			valb += 8;
			while (valb >= 0) {
			  out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
			  valb -= 6;
			}
			}
			if (valb > -6) {
			out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
			}
			return out;
		}

		string base64_url_decode(const string & in) {
			string out;
			vector<int> T(256, -1);
			unsigned int i;
			for (i =0; i < 64; i++) T[base64_url_alphabet[i]] = i;

			int val = 0, valb = -8;
			for (i = 0; i < in.length(); i++) {
			unsigned char c = in[i];
			if (T[c] == -1) break;
			val = (val<<6) + T[c];
			valb += 6;
			if (valb >= 0) {
			  out.push_back(char((val>>valb)&0xFF));
			  valb -= 8;
			}
			}
			return out;
		}

	private:

		string base64_url_alphabet;
};

class Request{

	public:

		Request() = default;

		Request(const string& host, const string& network_id, const unordered_map<string,string>& api_key_credentials){

			this->host = host;
			this->network_id = network_id;
			this->api_key_credentials = api_key_credentials;
			helper = RequestHelper();
			ORDER_FIELD_BIT_LENGTHS = {
			    {"asset_id_synthetic", 128},
			    {"asset_id_collateral", 250},
			    {"asset_id_fee", 250},
			    {"quantums_amount", 64},
			    {"nonce", 32},
			    {"position_id", 64},
			    {"expiration_epoch_hours", 32}
			};
			SYNTHETIC_ASSET_ID_MAP = {
			    {"BTC-USD", hex2BigInt("4254432d3130000000000000000000")},
			    {"ETH-USD", hex2BigInt("4554482d3900000000000000000000")},
			    {"LINK-USD", hex2BigInt("4c494e4b2d37000000000000000000")},
			    {"AAVE-USD", hex2BigInt("414156452d38000000000000000000")},
			    {"UNI-USD", hex2BigInt("554e492d3700000000000000000000")},
			    {"SUSHI-USD", hex2BigInt("53555348492d370000000000000000")},
			    {"SOL-USD", hex2BigInt("534f4c2d3700000000000000000000")},
			    {"YFI-USD", hex2BigInt("5946492d3130000000000000000000")},
			    {"ONEINCH-USD", hex2BigInt("31494e43482d370000000000000000")},
			    {"AVAX-USD", hex2BigInt("415641582d37000000000000000000")},
			    {"SNX-USD", hex2BigInt("534e582d3700000000000000000000")},
			    {"CRV-USD", hex2BigInt("4352562d3600000000000000000000")},
			    {"UMA-USD", hex2BigInt("554d412d3700000000000000000000")},
			    {"DOT-USD", hex2BigInt("444f542d3700000000000000000000")},
			    {"DOGE-USD", hex2BigInt("444f47452d35000000000000000000")},
			    {"MATIC-USD", hex2BigInt("4d415449432d360000000000000000")},
			    {"MKR-USD", hex2BigInt("4d4b522d3900000000000000000000")},
			    {"FIL-USD", hex2BigInt("46494c2d3700000000000000000000")},
			    {"ADA-USD", hex2BigInt("4144412d3600000000000000000000")},
			    {"ATOM-USD", hex2BigInt("41544f4d2d37000000000000000000")},
			    {"COMP-USD", hex2BigInt("434f4d502d38000000000000000000")},
			    {"BCH-USD", hex2BigInt("4243482d3800000000000000000000")},
			    {"LTC-USD", hex2BigInt("4c54432d3800000000000000000000")},
			    {"EOS-USD", hex2BigInt("454f532d3600000000000000000000")},
			    {"ALGO-USD", hex2BigInt("414c474f2d36000000000000000000")},
			    {"ZRX-USD", hex2BigInt("5a52582d3600000000000000000000")},
			    {"XMR-USD", hex2BigInt("584d522d3800000000000000000000")},
			    {"ZEC-USD", hex2BigInt("5a45432d3800000000000000000000")}
			};
			ASSET_RESOLUTION = {
				{"BTC-USD", 10},
			    {"ETH-USD", 9},
			    {"LINK-USD", 7},
			    {"AAVE-USD", 8},
			    {"UNI-USD", 7},
			    {"SUSHI-USD", 7},
			    {"SOL-USD", 7},
			    {"YFI-USD", 10},
			    {"ONEINCH-USD", 7},
			    {"AVAX-USD", 7},
			    {"SNX-USD", 7},
			    {"CRV-USD", 6},
			    {"UMA-USD", 7},
			    {"DOT-USD", 7},
			    {"DOGE-USD", 5},
			    {"MATIC-USD", 6},
			    {"MKR-USD", 9},
			    {"FIL-USD", 7},
			    {"ADA-USD", 6},
			    {"ATOM-USD", 7},
			    {"COMP-USD", 8},
			    {"BCH-USD", 8},
			    {"LTC-USD", 8},
			    {"EOS-USD", 6},
			    {"ALGO-USD", 6},
			    {"ZRX-USD", 6},
			    {"XMR-USD", 8},
			    {"ZEC-USD", 8}			    
			};

		}

		string sign_request(const string& request_path, const string& method, const string& iso_timestamp, const json& data){

			using namespace cryptlite;
			string mod_data = "";	// If data empty

			if (!data.empty())
				mod_data = helper.json2string(data);

	        string message_string = iso_timestamp + method + request_path + mod_data;

	        boost::uint8_t hmacsha256digest[sha256::HASH_SIZE];
			hmac<sha256>::calc(message_string, helper.base64_url_decode(this->api_key_credentials["secret"]), hmacsha256digest);

			string final_res = base64::encode_from_array(hmacsha256digest, sizeof(hmacsha256digest));

			return final_res;

    	}

		json request_processing(string method, const string& endpoint, const json& data){

		    string now_iso_string = helper.generate_now_iso();
		    now_iso_string.erase(remove(now_iso_string.begin(), now_iso_string.end(), '\n'), now_iso_string.end());
		    string request_path = "/v3/" + endpoint;
		    for_each(method.begin(), method.end(), [](char & c){
				c = ::toupper(c);
			});

		    cout << "Signing Request..." << endl;
		    string signature = sign_request(request_path, method, now_iso_string, data);
		    cout << "Request Signed" << endl;

		    json headers = {
		        {"DYDX-SIGNATURE", signature},
		        {"DYDX-API-KEY", api_key_credentials["key"]},
		        {"DYDX-TIMESTAMP", now_iso_string},
		        {"DYDX-PASSPHRASE", api_key_credentials["passphrase"]},
		    };

		    return helper.request(host + request_path, method, headers, data);
		}

		json postOrder(const string& endpoint, const json& data){
		    return request_processing("post", endpoint, data);
		}

		string convertBigIntToString(uint1024_t num){
			stringstream os;
			os << num;
			return os.str();
		}

		uint1024_t hex2BigInt(const string& hexString){
			uint1024_t finalNum;
	        stringstream ss;
	        for(int c: hexString){
				ss << hex << c;
			}
			ss >> finalNum;
			return finalNum;
		}

		uint1024_t calculate_hash_signable_order(const json& order, int position_id){

			// Ropsten Collateral Value
			uint1024_t collateral_asset_id = hex2BigInt("02c04d8b650f44092278a7cb1e1028c82025dff622db96c934b611b84cc8de5a");
			uint1024_t asset_id_collateral = collateral_asset_id;
            uint1024_t asset_id_fee = collateral_asset_id;

            uint1024_t asset_id_synthetic = SYNTHETIC_ASSET_ID_MAP[order["market"].get<string>()];

            double total_amount = stod(order["price"].get<string>()) * stod(order["size"].get<string>());
            int quantums_amount_collateral = (int)(total_amount * pow(10, 6));
            int quantums_amount_synthetic = (int)(total_amount * pow(10, ASSET_RESOLUTION[order["market"].get<string>()]));

            int expiration_epoch_seconds = stoi(order["expiration"].get<string>());
            int expiration_epoch_hours = ceil(float(expiration_epoch_seconds) / 3600) + (24 * 7);

            uint1024_t asset_id_sell, asset_id_buy, quantums_amount_sell, quantums_amount_buy;
            uint1024_t quantums_amount_fee = int(stod(order["limit_fee"].get<string>()) * quantums_amount_collateral);

			if(order["side"].get<string>() == "BUY"){
				asset_id_sell = asset_id_collateral;
	            asset_id_buy = asset_id_synthetic;
	            quantums_amount_sell = quantums_amount_collateral;
	            quantums_amount_buy = quantums_amount_synthetic;
			}
			else{
	            asset_id_sell = asset_id_synthetic;
	            asset_id_buy = asset_id_collateral;
	            quantums_amount_sell = quantums_amount_synthetic;
	            quantums_amount_buy = quantums_amount_collateral;
        	}

        	uint1024_t nonce = hex2BigInt(cryptlite::sha256::hash_hex(order["client_id"].get<string>()));

	        uint1024_t part_1 = quantums_amount_sell;
	        part_1 <<= ORDER_FIELD_BIT_LENGTHS["quantums_amount"];
	        part_1 += quantums_amount_buy;
	        part_1 <<= ORDER_FIELD_BIT_LENGTHS["quantums_amount"];
	        part_1 += quantums_amount_fee;
	        part_1 <<= ORDER_FIELD_BIT_LENGTHS["nonce"];
	        part_1 += nonce;

	        uint1024_t part_2 = 3;
	        for(int i = 0; i < 3; i++){
	            part_2 <<= ORDER_FIELD_BIT_LENGTHS["position_id"];
	            part_2 += position_id;
	        }
	        part_2 <<= ORDER_FIELD_BIT_LENGTHS["expiration_epoch_hours"];
	        part_2 += expiration_epoch_seconds;
	        part_2 <<= 17;

	        // cout << "Hash v2: " << get_hash(asset_id_sell, asset_id_buy);

	        uint1024_t assets_hash = get_hash(
	            get_hash(
	                asset_id_sell,
	                asset_id_buy
	            ),
	            asset_id_fee
	        );

	        return get_hash(
	            get_hash(
	                assets_hash,
	                part_1
	            ),
	            part_2
	        );

		}

		uint1024_t get_hash(uint1024_t left, uint1024_t right){

			char assets_hash[251]{};

			char lbytes[32];
			std::copy(static_cast<const char*>(static_cast<const void*>(&left)),
			          static_cast<const char*>(static_cast<const void*>(&left)) + 32,
			          lbytes);

			cout << lbytes << endl;

			char rbytes[32];
			std::copy(static_cast<const char*>(static_cast<const void*>(&right)),
			          static_cast<const char*>(static_cast<const void*>(&right)) + 32,
			          rbytes);

			cout << rbytes << endl;

	        int res = starkware::Hash((gsl::byte*)lbytes, (gsl::byte*)rbytes, (gsl::byte*)assets_hash);
	        cout << assets_hash << endl;

			if(res != 0){
				cout << "Error while calculating hash" << endl;
			}

			return hex2BigInt(assets_hash);

		}


		bool createOrder(const string& stark_private_key, const string& position_id, const string& market, const string& order_price, const string& order_size, const string& side, const string& type="LIMIT"){
			
			string client_id = to_string(rand());
			string expiration = to_string(time(0) + 10);	
			unsigned char stark_sign_output[251]="";
			unsigned char assets_hash[251]="";

			string asset_qty = to_string(stod(order_size)*stod(order_price));

	        int res1 = starkware::Hash((gsl::byte*)position_id.c_str(),(gsl::byte*)asset_qty.c_str(), (gsl::byte*)assets_hash);

			if(res1 !=0){
				cout << "Hash generation failed" << endl;
				return false;
			}


			stringstream hash, stark_sign;
			uint1024_t hash_val, stark_val;
			for(int c: assets_hash){
				hash << hex << c;
			}
			cout << "Hash v1:" << hash.str() << endl;
			hash >> hash_val;
			cout << "Hash Value:" << hash_val << endl;


	        uint1024_t private_num = hex2BigInt(stark_private_key);
	        
	        cout << "\nPrivate Key Value: " << private_num << endl;

			int res2 = starkware::Sign((gsl::byte*)convertBigIntToString(private_num).c_str(), (gsl::byte*)assets_hash, (gsl::byte*)to_string(rand()).c_str(), (gsl::byte*)stark_sign_output);

			if(res2 !=0){
				cout << "STARK Private Key Signing failed" << endl;
				return false;
			}

			for(int c: stark_sign_output){
				stark_sign << hex << c;
			}
			cout << "\nStark Key Sign:" << stark_sign.str() << endl;
			stark_sign >> stark_val;
			cout << "Stark Key Value:" << stark_val << endl;

		    json order = {
		        {"market", market},
		        {"side", side},
		        {"type", type},
		        {"size", order_size},
		        {"price", order_price},
		        {"limit_fee", "0.0015"},
		        {"expiration", expiration},
		        {"client_id", client_id},
		        {"signature", stark_sign.str()}
		    };

		    cout << order << endl;

		    // cout << calculate_hash_signable_order(order, stoi(position_id)) << endl;

		    json ans = postOrder("orders", order);

		    if(ans.empty())
		    	return false;
		    else
		    	return true;
		}

	private:

		string host;
		string network_id;
		unordered_map<string,string> api_key_credentials;
		RequestHelper helper;
		unordered_map<string, int> ORDER_FIELD_BIT_LENGTHS;
		unordered_map<string, uint1024_t> SYNTHETIC_ASSET_ID_MAP;
		unordered_map<string, int> ASSET_RESOLUTION;

};

int main(){

	// Ganache test address.
    string ETHEREUM_ADDRESS = "0x83854e386cBc4E924d447a7AC06E50A4C0d6DC9d";

    string API_HOST_ROPSTEN = "https://api.stage.dydx.exchange";

    string NETWORK_ID_ROPSTEN = "3";

    string stark_private_key = "753d116e812ad750ab10a718ef7bbefb96cb743a8bdf93fd2c27b105eda336e";

	unordered_map<string,string> api_credentials = {{"secret", "_0-ba_Cdx9NQTANIRh7neKEnxubFRmMvoISfg8k4"}, {"key", "00112342-5a99-4869-a412-57347ca42672"}, {"passphrase", "8u00r_rAlGgMNLz8arjq"}};

	Request reqObj(API_HOST_ROPSTEN, NETWORK_ID_ROPSTEN, api_credentials);

	if (reqObj.createOrder(stark_private_key, "56541", "BTC-USD", "45000", "0.17", "BUY")){
		cout << "Order created successfully" << endl;
	}
	else{
		cout << "Failure in creating the order successfully" << endl;
	}
	return 0;
}

