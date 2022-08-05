use quora;

create event ClearExpiredToken
on schedule every 1 day
comment 'Nettoyage de la table reset password tous les jours'
do
delete from quora.reset_password where expired_at < now();