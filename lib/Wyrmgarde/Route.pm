package Wyrmgarde::Route;

use strict;
use warnings;
use utf8;
use Wyrmgarde::User;
use Wyrmgarde::Vault;

sub user_check {
	my ($c) = @_;
	unless ($c->session('username')) {
		$c->flash(info => 'You have been logged out.');
		$c->redirect_to('/login');
		return 0;
	}
	return 1;
}

sub admin_check {
	my ($c) = @_;
	user_check($c) or return 0;
	unless ($c->session('username') eq 'admin') {
		$c->flash(err => 'Unauthorized.');
		$c->redirect_to('/home');
		return 0;
	}
	return 1;
}

sub register {
	my ($app, $dbh, $key) = @_;
	my $logger = $app->log;

	$app->routes->get('/' => sub {
		my $c = shift;
		$c->redirect_to('/login');
	});

	$app->routes->get('/login' => sub {
		my $c = shift;
		$c->render(template => 'login');
	});

	$app->routes->post('/login' => sub {
		my $c = shift;
		my $username = $c->param('username');
		my $password = $c->param('password');
		Wyrmgarde::User::auth($username, $password, $dbh, $logger)
			  ? do {
				$logger->info("User '$username' logged in");
				my ($sec, $min, $hour) = localtime();
				my $time = sprintf("%02d:%02d:%02d", $hour, $min, $sec,);
				$c->session(username => $username, login_time => $time, expiration => 3600);
				$c->flash(ok => 'Welcome, ' . $username . '.');
				$c->redirect_to('/home');
			} : do {
				$c->flash(err => 'Invalid username or password.');
				$c->redirect_to('/login');
			};
	});

	$app->routes->get('/logout' => sub {
		my $c = shift;
		$c->flash(info => 'You have been logged out.');
		$c->redirect_to('/login');
	});

	$app->routes->post('/logout' => sub {
		my $c = shift;
		$c->session(expires => 1);
		$c->redirect_to('/logout');
	});

	$app->routes->get('/home' => sub {
		my $c = shift;
		user_check($c) or return 0;
		my $s_username = $c->session('username');
		$c->stash(s_username => $s_username);
		$c->stash(login_time => $c->session('login_time'));
		$c->render(template => 'home');
	});

	$app->routes->get('/vault/search_password' => sub {
		my $c = shift;
		user_check($c) or return 0;
		my $s_username = $c->session('username');
		$c->stash(s_username => $s_username);
		my @passwords = Wyrmgarde::Vault::access($s_username, $dbh, $logger);
		$c->stash(passwords => \@passwords);
		$c->render(template => 'vault-search_password');
	});

	$app->routes->get('/user/user_profile' => sub {
		my $c = shift;
		user_check($c) or return 0;
		my $s_username = $c->session('username');
		my @user_roles = Wyrmgarde::User::user_roles($dbh, $s_username);
		my $user_roles = join(', ', @user_roles);
		$c->stash(s_username => $s_username);
		$c->stash(user_roles => $user_roles);
		$c->render(template => 'user-user_profile');
	});

	$app->routes->get('/user/change_password' => sub {
		my $c = shift;
		user_check($c) or return 0;
		my $s_username = $c->session('username');
		$c->stash(s_username => $s_username);
		$c->render(template => 'user-change_password');
	});

	$app->routes->post('/user/change_password' => sub {
		my $c = shift;
		user_check($c) or return 0;
		my $s_username = $c->session('username');
		my $old_password = $c->param('old_password');
		my $new_password = $c->param('new_password');
		Wyrmgarde::User::auth($s_username, $old_password, $dbh, $logger)
			or do {
				$c->flash(err => 'Invalid password.');
				$c->redirect_to('/user/change_password');
				return 0;
			};
		Wyrmgarde::User::edit_password($s_username, $new_password, $dbh, $logger)
			  ? do {
				$c->flash(ok => 'Password changed.');
				$c->redirect_to('/home');
			} : do {
				$c->flash(err => 'Password unchanged. Please contact the administrator.');
				$c->redirect_to('/home');
			};
	});

	$app->routes->get('/admin/insert_password' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $s_username = $c->session('username');
		my @all_roles = Wyrmgarde::User::all_roles($dbh);
		$c->stash(s_username => $s_username);
		$c->stash(roles => \@all_roles);
		$c->render(template => 'admin-insert_password');
	});

	$app->routes->post('/admin/insert_password' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $name  = $c->param('name');
		my $comment  = $c->param('comment');
		my $password  = $c->param('password');
		my $roles_ref = $c->every_param('role');
		my @roles     = @$roles_ref;
		my $roles     = join(',', @roles);
		my $roles_str = $roles;
		$roles_str =~ s/,/, /g;
		Wyrmgarde::Vault::insert($name, $comment, $password, $roles, $key, $dbh, $logger)
		  ? do {
			$c->flash(ok => 'Password \'' . $name . '\' inserted with roles: ' . $roles_str . '.');
			$c->redirect_to('/home');
		} : do {
			$c->flash(err => 'Password insertion failed: ' . $name. '.');
			$c->redirect_to('/home');
		};
	});

	$app->routes->get('/admin/user_profile' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $s_username = $c->session('username');
		my $a_username  = $c->param('username');
		my @user_roles = Wyrmgarde::User::user_roles($dbh, $a_username);
		my $user_roles = join(', ', @user_roles);
		$c->stash(s_username => $s_username);
		$c->stash(a_username => $a_username);
		$c->stash(user_roles => $user_roles);
		$c->render(template => 'admin-user_profile');
	});

	$app->routes->get('/admin/create_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $s_username = $c->session('username');
		my @all_roles = Wyrmgarde::User::all_roles($dbh);
		$c->stash(s_username => $s_username);
		$c->stash(roles => \@all_roles);
		$c->render(template => 'admin-create_user');
	});

	$app->routes->post('/admin/create_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $a_username  = $c->param('username');
		my $password  = $c->param('password');
		my $roles_ref = $c->every_param('role');
		my @roles     = @$roles_ref;
		my $roles     = join(',', @roles);
		my $roles_str = $roles;
		$roles_str =~ s/,/, /g;
		Wyrmgarde::User::create($a_username, $password, $roles, $dbh, $logger)
		  ? do {
			$c->flash(ok => 'User \'' . $a_username . '\' created with roles: ' . $roles_str . '.');
			$c->redirect_to('/home');
		} : do {
			$c->flash(err => 'User creation failed: ' . $a_username. '.');
			$c->redirect_to('/home');
		};
	});

	$app->routes->get('/admin/search_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $s_username = $c->session('username');
		$c->stash(s_username => $s_username);
		my @users = Wyrmgarde::User::get($dbh, $logger);
		$c->stash(users => \@users);
		$c->render(template => 'admin-search_user');
	});

	$app->routes->get('/admin/edit_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $s_username = $c->session('username');
		$c->stash(s_username => $s_username);
		my $a_username = $c->param('username');
		Wyrmgarde::User::check($a_username, $dbh, $logger) or do {
			$c->flash(err => 'User does not exist: ' . $a_username . '.');
			$c->redirect_to('/home');
		};
		my @all_roles = Wyrmgarde::User::all_roles($dbh);
		my @user_roles = Wyrmgarde::User::user_roles($dbh, $a_username);
		$c->stash(a_username => $a_username);
		$c->stash(all_roles => \@all_roles);
		$c->stash(user_roles => \@user_roles);
		$c->render(template => 'admin-edit_user');
	});

	$app->routes->post('/admin/edit_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $a_username = $c->param('username');
		my $new_username = $c->param('new_username');
		my $new_password = $c->param('new_password');
		my $new_roles_ref = $c->every_param('role');
		my @new_roles = @$new_roles_ref;
		my $new_roles     = join(',', @new_roles);
		unless ($new_username eq $a_username) {
			Wyrmgarde::User::edit_username($a_username, $new_username, $dbh, $logger);
		}
		unless ($new_password eq "") {
			Wyrmgarde::User::edit_password($new_username, $new_password, $dbh, $logger);
		}
		Wyrmgarde::User::edit_roles($new_username, $new_roles, $dbh, $logger);
		$c->flash(ok => 'User edited: ' . $new_username . ' (' . $a_username . ').');
		$c->redirect_to('/home');
	});

	$app->routes->get('/admin/delete_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $s_username = $c->session('username');
		$c->stash(s_username => $s_username);
		my $a_username = $c->param('username');
		Wyrmgarde::User::check($a_username, $dbh, $logger) or do {
			$c->flash(err => 'User does not exist: ' . $a_username . '.');
			$c->redirect_to('/home');
		};
		$c->stash(a_username => $a_username);
		$c->render(template => 'admin-delete_user');
	});

	$app->routes->post('/admin/delete_user' => sub {
		my $c = shift;
		admin_check($c) or return 0;
		my $a_username = $c->param('username');
		Wyrmgarde::User::delete($a_username, $dbh, $logger)
		  ? do {
			$c->flash(ok => 'User deleted: ' . $a_username . '.');
			$c->redirect_to('/home');
		} : do {
			$c->flash(err => 'Used not deleted: ' . $a_username. '.');
			$c->redirect_to('/home');
		};
	});

#	$app->routes->get('/vault' => sub {
#		my $c = shift;
#		my $vault_username = $c->session('username');
#		my $sth = $dbh->prepare("
#			SELECT p.name
#			FROM passwords p
#			JOIN password_roles pr ON p.id = pr.password_id
#			JOIN roles r ON pr.role_id = r.id
#			JOIN user_roles ur ON r.id = ur.role_id
#			JOIN users u ON ur.user_id = u.id
#			WHERE u.username = ?
#		");
#		$sth->execute($vault_username);
#		my @passwords = @{$sth->fetchall_arrayref};
#		$c->render(template => 'vault', passwords => \@passwords);
#	});
}

1;
