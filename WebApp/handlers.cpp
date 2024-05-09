#include "handlers.h"

#include <vector>

#include "rendering.h"

// register an orm mapping (to convert the db query results into
// json objects).
// the db query results contain several rows, each has a number of
// fields. the order of `make_db_field<Type[i]>(name[i])` in the
// initializer list corresponds to these fields (`Type[0]` and
// `name[0]` correspond to field[0], `Type[1]` and `name[1]`
// correspond to field[1], ...). `Type[i]` is the type you want
// to convert the field value to, and `name[i]` is the identifier
// with which you want to store the field in the json object, so
// if the returned json object is `obj`, `obj[name[i]]` will have
// the type of `Type[i]` and store the value of field[i].
bserv::db_relation_to_object orm_user{
	bserv::make_db_field<std::int64_t>("id"),
	bserv::make_db_field<std::string>("name"),
	bserv::make_db_field<std::string>("password"),
	bserv::make_db_field<std::string>("email")
};

bserv::db_relation_to_object orm_restaurant{
	bserv::make_db_field<std::int64_t>("id"),
    bserv::make_db_field<std::int64_t>("user_id"),
	bserv::make_db_field<std::string>("name"),
	bserv::make_db_field<std::string>("address"),
	bserv::make_db_field<std::string>("contact")
};

std::optional<boost::json::object> get_user(
	bserv::db_transaction& tx,
	const boost::json::string& email) {
	bserv::db_result r = tx.exec(
		"select * from auth_user where email = ?", email);
	lginfo << r.query(); // this is how you log info
	return orm_user.convert_to_optional(r);
}

std::optional<boost::json::object> get_user_from_password(
	bserv::db_transaction& tx,
	const boost::json::string& email,
    const boost::json::string& password) {
	bserv::db_result r = tx.exec(
		"select * from auth_user where email = ? and password = ?", email, password);
	lginfo << r.query(); // this is how you log info
	return orm_user.convert_to_optional(r);
}

std::vector<boost::json::object> get_restaurants(
	bserv::db_transaction& tx,
	const boost::json::string& email,
    const boost::json::string& password) {
    auto user = get_user_from_password(tx, email, password);
    if (user.has_value()) {
        bserv::db_result r = tx.exec(
            "select * from ? where user_id = ?", bserv::db_name("restaurants"), user.value()["id"].as_int64());
        lginfo << r.query(); // this is how you log info
        return orm_restaurant.convert_to_vector(r);
        
    } else {
        return {};
    }
}

std::optional<boost::json::object> get_restaurant(
	bserv::db_transaction& tx,
	const boost::json::string& email,
    const boost::json::string& password,
    const int64_t& restaurant_id) {
    auto user = get_user_from_password(tx, email, password);
    if (user.has_value()) {
        bserv::db_result r = tx.exec(
            "select * from ? where user_id = ? and id = ?", bserv::db_name("restaurants"), user.value()["id"].as_int64(), restaurant_id);
        lginfo << r.query(); // this is how you log info
        return orm_restaurant.convert_to_optional(r);
        
    } else {
        return {};
    }
}

void add_restaurant(
	bserv::db_transaction& tx,
	const boost::json::string& email,
    const boost::json::string& password,
    const boost::json::string& name,
    const boost::json::string& address,
    const boost::json::string& contact) {
    auto user = get_user_from_password(tx, email, password);
    if (user.has_value()) {
        bserv::db_result r = tx.exec(
            "insert into ? (user_id, name, address, contact) values (?, ?, ?, ?)", bserv::db_name("restaurants"), user.value()["id"].as_int64(), name, address, contact);
        lginfo << r.query(); // this is how you log info
    }
}

void del_restaurant(
	bserv::db_transaction& tx,
	const boost::json::string& email,
    const boost::json::string& password,
    const int& restaurant_id) {
    auto user = get_user_from_password(tx, email, password);
    if (user.has_value()) {
        bserv::db_result r = tx.exec(
            "delete from restaurants where user_id = ? and id = ?", user.value()["id"].as_int64(), restaurant_id);
        lginfo << r.query(); // this is how you log info
    }
}

void update_restaurant(
	bserv::db_transaction& tx,
	const boost::json::string& email,
    const boost::json::string& password,
    const std::int64_t& restaurant_id,
    const boost::json::string& name,
    const boost::json::string& address,
    const boost::json::string& contact) {
    auto user = get_user_from_password(tx, email, password);
    if (user.has_value()) {
        bserv::db_result r = tx.exec(
            "update restaurants set name = ?, address = ?, contact = ? where user_id = ? and id = ?",  name, address, contact, user.value()["id"].as_int64(), restaurant_id);
        lginfo << r.query(); // this is how you log info
    }
}

std::string get_or_empty(
	boost::json::object& obj,
	const std::string& key) {
	return obj.count(key) ? obj[key].as_string().c_str() : "";
}

// if you want to manually modify the response,
// the return type should be `std::nullopt_t`,
// and the return value should be `std::nullopt`.
std::nullopt_t hello(
	bserv::response_type& response,
	std::shared_ptr<bserv::session_type> session_ptr) {
	bserv::session_type& session = *session_ptr;
	boost::json::object obj;
	if (session.count("user")) {
		// NOTE: modifications to sessions must be performed
		// BEFORE referencing objects in them. this is because
		// modifications might invalidate referenced objects.
		// in this example, "count" might be added to `session`,
		// which should be performed first.
		// then `user` can be referenced safely.
		if (!session.count("count")) {
			session["count"] = 0;
		}
		auto& user = session["user"].as_object();
		session["count"] = session["count"].as_int64() + 1;
		obj = {
			{"welcome", user["name"]},
			{"count", session["count"]}
		};
	}
	else {
		obj = { {"msg", "hello, world!"} };
	}
	// the response body is a string,
	// so the `obj` should be serialized
	response.body() = boost::json::serialize(obj);
	response.prepare_payload(); // this line is important!
	return std::nullopt;
}
// 
// if you return a json object, the serialization
// is performed automatically.
boost::json::object user_register(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	if (params.count("username") == 0) {
		return {
			{"success", false},
			{"message", "`username` is required"}
		};
	}
	if (params.count("password") == 0) {
		return {
			{"success", false},
			{"message", "`password` is required"}
		};
	}
	auto username = params["username"].as_string();
	bserv::db_transaction tx{ conn };
	auto opt_user = get_user(tx, username);
	if (opt_user.has_value()) {
		return {
			{"success", false},
			{"message", "`username` existed"}
		};
	}
	auto password = params["password"].as_string();
	bserv::db_result r = tx.exec(
		"insert into ? "
		"(?, password, is_superuser, "
		"first_name, last_name, email, is_active) values "
		"(?, ?, ?, ?, ?, ?, ?)", bserv::db_name("auth_user"),
		bserv::db_name("username"),
		username,
		bserv::utils::security::encode_password(
			password.c_str()), false,
		get_or_empty(params, "first_name"),
		get_or_empty(params, "last_name"),
		get_or_empty(params, "email"), true);
	lginfo << r.query();
	tx.commit(); // you must manually commit changes
	return {
		{"success", true},
		{"message", "user registered"}
	};
}

// if you return a json object, the serialization
// is performed automatically.
boost::json::object a_function_user_register(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	if (params.count("email") == 0) {
		return {};
	}
	if (params.count("password") == 0) {
		return {};
	}
	auto name = params["name"].as_string();
	auto email = params["email"].as_string();
	bserv::db_transaction tx{ conn };
	auto opt_user = get_user(tx, email);
	if (opt_user.has_value()) {
		return {};
	}
	auto password = params["password"].as_string();
	bserv::db_result r = tx.exec(
		"insert into ? "
		"(name, password, "
		"email) values "
		"(?, ?, ?)", bserv::db_name("auth_user"),
		name,
        password,
        email);
	lginfo << r.query();
	tx.commit(); // you must manually commit changes
    return {
        {"email", params["email"].as_string()},
        {"password", params["password"].as_string()},
        {"name", params["name"].as_string()}
    };
}

boost::json::object user_login(
	bserv::request_type& request,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	if (params.count("username") == 0) {
		return {
			{"success", false},
			{"message", "`username` is required"}
		};
	}
	if (params.count("password") == 0) {
		return {
			{"success", false},
			{"message", "`password` is required"}
		};
	}
	auto username = params["username"].as_string();
	bserv::db_transaction tx{ conn };
	auto opt_user = get_user(tx, username);
	if (!opt_user.has_value()) {
		return {
			{"success", false},
			{"message", "invalid username/password"}
		};
	}
	auto& user = opt_user.value();
	if (!user["is_active"].as_bool()) {
		return {
			{"success", false},
			{"message", "invalid username/password"}
		};
	}
	auto password = params["password"].as_string();
	auto encoded_password = user["password"].as_string();
	if (!bserv::utils::security::check_password(
		password.c_str(), encoded_password.c_str())) {
		return {
			{"success", false},
			{"message", "invalid username/password"}
		};
	}
	bserv::session_type& session = *session_ptr;
	session["user"] = user;
	return {
		{"success", true},
		{"message", "login successfully"}
	};
}

boost::json::object a_function_user_login(
	bserv::request_type& request,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (request.method() != boost::beast::http::verb::post) {
		throw bserv::url_not_found_exception{};
	}
	if (params.count("email") == 0) {
		return {};
	}
	if (params.count("password") == 0) {
		return {};
	}
	auto email = params["email"].as_string();
	auto password = params["password"].as_string();
	bserv::db_transaction tx{ conn };
	auto opt_user = get_user_from_password(tx, email, password);
	if (!opt_user.has_value()) {
		return {};
	}
	auto& user = opt_user.value();
    return user;
}

// if you return a json object, the serialization
// is performed automatically.
boost::json::array a_function_restaurants(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (params.count("email") == 0) {
		return {};
	}
	if (params.count("password") == 0) {
		return {};
	}
	bserv::db_transaction tx{ conn };
	auto email = params["email"].as_string();
	auto password = params["password"].as_string();
    if (request.method() == boost::beast::http::verb::put) {
        update_restaurant(tx, email, password, params["id"].as_int64(), params["name"].as_string(), params["address"].as_string(), params["contact"].as_string());
        tx.commit();
        return {};
    } else if (request.method() == boost::beast::http::verb::post) {
        add_restaurant(tx, email, password, params["name"].as_string(), params["address"].as_string(), params["contact"].as_string());
        tx.commit();
        return {};
    } else if (request.method() == boost::beast::http::verb::delete_) {
        del_restaurant(tx, email, password, params["id"].as_int64());
        tx.commit();
        return {};
    } else {
		throw bserv::url_not_found_exception{};
	}
}

// if you return a json object, the serialization
// is performed automatically.
boost::json::array a_function_delete_restaurant(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (params.count("email") == 0) {
		return {};
	}
	if (params.count("password") == 0) {
		return {};
	}
	bserv::db_transaction tx{ conn };
	auto email = params["email"].as_string();
	auto password = params["password"].as_string();
    if (request.method() == boost::beast::http::verb::post) {
        del_restaurant(tx, email, password, params["id"].as_int64());
        tx.commit();
        return {};
    } else {
		throw bserv::url_not_found_exception{};
	}
}

// if you return a json object, the serialization
// is performed automatically.
boost::json::array a_function_query_restaurants(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (params.count("email") == 0) {
		return {};
	}
	if (params.count("password") == 0) {
		return {};
	}
	bserv::db_transaction tx{ conn };
	auto email = params["email"].as_string();
	auto password = params["password"].as_string();
    if (request.method() == boost::beast::http::verb::post) {
        // fetch restaurants
        auto res = get_restaurants(tx, email, password);
        boost::json::array ret;
        for (auto&& obj : res) {
            ret.push_back(obj);
        }
        return ret;
    } else {
		throw bserv::url_not_found_exception{};
	}
}

// if you return a json object, the serialization
// is performed automatically.
boost::json::object a_function_query_restaurant(
	bserv::request_type& request,
	// the json object is obtained from the request body,
	// as well as the url parameters
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn) {
	if (params.count("email") == 0) {
		return {};
	}
	if (params.count("password") == 0) {
		return {};
	}
	bserv::db_transaction tx{ conn };
	auto email = params["email"].as_string();
	auto password = params["password"].as_string();
    if (request.method() == boost::beast::http::verb::post) {
        // fetch restaurants
        auto res = get_restaurant(tx, email, password, params["id"].as_int64());
        if (res.has_value()) {
            return res.value();
        } else {
            return {};
        }
    } else {
		throw bserv::url_not_found_exception{};
	}
}

boost::json::object find_user(
	std::shared_ptr<bserv::db_connection> conn,
	const std::string& name) {
	bserv::db_transaction tx{ conn };
	auto user = get_user(tx, name.c_str());
	if (!user.has_value()) {
		return {
			{"success", false},
			{"message", "requested user does not exist"}
		};
	}
	user.value().erase("id");
	user.value().erase("password");
	return {
		{"success", true},
		{"user", user.value()}
	};
}

boost::json::object user_logout(
	std::shared_ptr<bserv::session_type> session_ptr) {
	bserv::session_type& session = *session_ptr;
	if (session.count("user")) {
		session.erase("user");
	}
	return {
		{"success", true},
		{"message", "logout successfully"}
	};
}

boost::json::object send_request(
	std::shared_ptr<bserv::session_type> session,
	std::shared_ptr<bserv::http_client> client_ptr,
	boost::json::object&& params) {
	// post for response:
	// auto res = client_ptr->post(
	//     "localhost", "8080", "/echo", {{"msg", "request"}}
	// );
	// return {{"response", boost::json::parse(res.body())}};
	// -------------------------------------------------------
	// - if it takes longer than 30 seconds (by default) to
	// - get the response, this will raise a read timeout
	// -------------------------------------------------------
	// post for json response (json value, rather than json
	// object, is returned):
	auto obj = client_ptr->post_for_value(
		"localhost", "8080", "/echo", { {"request", params} }
	);
	if (session->count("cnt") == 0) {
		(*session)["cnt"] = 0;
	}
	(*session)["cnt"] = (*session)["cnt"].as_int64() + 1;
	return { {"response", obj}, {"cnt", (*session)["cnt"]} };
}

boost::json::object echo(
	boost::json::object&& params) {
	return { {"echo", params} };
}

// websocket
std::nullopt_t ws_echo(
	std::shared_ptr<bserv::session_type> session,
	std::shared_ptr<bserv::websocket_server> ws_server) {
	ws_server->write_json((*session)["cnt"]);
	while (true) {
		try {
			std::string data = ws_server->read();
			ws_server->write(data);
		}
		catch (bserv::websocket_closed&) {
			break;
		}
	}
	return std::nullopt;
}


std::nullopt_t serve_static_files(
	bserv::response_type& response,
	const std::string& path) {
	return serve(response, path);
}


std::nullopt_t index(
	const std::string& template_path,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	boost::json::object& context) {
	bserv::session_type& session = *session_ptr;
	if (session.contains("user")) {
		context["user"] = session["user"];
	}
	return render(response, template_path, context);
}

std::nullopt_t index_page(
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response) {
	boost::json::object context;
	return index("index.html", session_ptr, response, context);
}

std::nullopt_t form_login(
	bserv::request_type& request,
	bserv::response_type& response,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	lgdebug << params << std::endl;
	auto context = user_login(request, std::move(params), conn, session_ptr);
	lginfo << "login: " << context << std::endl;
	return index("index.html", session_ptr, response, context);
}

std::nullopt_t form_logout(
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response) {
	auto context = user_logout(session_ptr);
	lginfo << "logout: " << context << std::endl;
	return index("index.html", session_ptr, response, context);
}

std::nullopt_t redirect_to_users(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	int page_id,
	boost::json::object&& context) {
	lgdebug << "view users: " << page_id << std::endl;
	bserv::db_transaction tx{ conn };
	bserv::db_result db_res = tx.exec("select count(*) from auth_user;");
	lginfo << db_res.query();
	std::size_t total_users = (*db_res.begin())[0].as<std::size_t>();
	lgdebug << "total users: " << total_users << std::endl;
	int total_pages = (int)total_users / 10;
	if (total_users % 10 != 0) ++total_pages;
	lgdebug << "total pages: " << total_pages << std::endl;
	db_res = tx.exec("select * from auth_user limit 10 offset ?;", (page_id - 1) * 10);
	lginfo << db_res.query();
	auto users = orm_user.convert_to_vector(db_res);
	boost::json::array json_users;
	for (auto& user : users) {
		json_users.push_back(user);
	}
	boost::json::object pagination;
	if (total_pages != 0) {
		pagination["total"] = total_pages;
		if (page_id > 1) {
			pagination["previous"] = page_id - 1;
		}
		if (page_id < total_pages) {
			pagination["next"] = page_id + 1;
		}
		int lower = page_id - 3;
		int upper = page_id + 3;
		if (page_id - 3 > 2) {
			pagination["left_ellipsis"] = true;
		}
		else {
			lower = 1;
		}
		if (page_id + 3 < total_pages - 1) {
			pagination["right_ellipsis"] = true;
		}
		else {
			upper = total_pages;
		}
		pagination["current"] = page_id;
		boost::json::array pages_left;
		for (int i = lower; i < page_id; ++i) {
			pages_left.push_back(i);
		}
		pagination["pages_left"] = pages_left;
		boost::json::array pages_right;
		for (int i = page_id + 1; i <= upper; ++i) {
			pages_right.push_back(i);
		}
		pagination["pages_right"] = pages_right;
		context["pagination"] = pagination;
	}
	context["users"] = json_users;
	return index("users.html", session_ptr, response, context);
}

std::nullopt_t view_users(
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr,
	bserv::response_type& response,
	const std::string& page_num) {
	int page_id = std::stoi(page_num);
	boost::json::object context;
	return redirect_to_users(conn, session_ptr, response, page_id, std::move(context));
}

std::nullopt_t form_add_user(
	bserv::request_type& request,
	bserv::response_type& response,
	boost::json::object&& params,
	std::shared_ptr<bserv::db_connection> conn,
	std::shared_ptr<bserv::session_type> session_ptr) {
	boost::json::object context = user_register(request, std::move(params), conn);
	return redirect_to_users(conn, session_ptr, response, 1, std::move(context));
}
