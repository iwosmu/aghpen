<?php
// Room booking system "RoomBooker": a typical forgotten departmental app.
session_start();
$_SESSION['visits'] = ($_SESSION['visits'] ?? 0) + 1;
?>
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>System Rezerwacji Sal</title></head>
<body>
<h1>System Rezerwacji Sal</h1>
<form method="get" action="/index.php">
  <label>Login <input name="login"></label>
  <label>Hasło <input type="password" name="haslo"></label>
  <button type="submit">Zaloguj</button>
</form>
<p class="footer">Powered by RoomBooker 1.2.3 &copy; 2016</p>
</body>
</html>
