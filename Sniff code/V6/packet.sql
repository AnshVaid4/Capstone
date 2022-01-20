-- phpMyAdmin SQL Dump
-- version 4.9.2
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jan 20, 2022 at 08:37 AM
-- Server version: 10.4.10-MariaDB
-- PHP Version: 7.1.33

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `capstone`
--

-- --------------------------------------------------------

--
-- Table structure for table `packet`
--

CREATE TABLE `packet` (
  `id` int(11) NOT NULL,
  `sourceip` varchar(16) NOT NULL,
  `destinationip` varchar(16) NOT NULL,
  `sourceport` int(11) NOT NULL,
  `destinationport` int(11) NOT NULL,
  `packetlength` int(11) NOT NULL,
  `packetttl` int(11) NOT NULL,
  `os` varchar(2) NOT NULL,
  `protocol` varchar(4) NOT NULL,
  `flags` varchar(6) NOT NULL,
  `date` date NOT NULL,
  `time` time NOT NULL,
  `comments` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `packet`
--

INSERT INTO `packet` (`id`, `sourceip`, `destinationip`, `sourceport`, `destinationport`, `packetlength`, `packetttl`, `os`, `protocol`, `flags`, `date`, `time`, `comments`) VALUES
(1, '192.168.43.6', '52.41.99.97', 59681, 443, 40, 128, 'W', 'TCP', 'FA', '2022-01-20', '12:30:53', '[IP]'),
(2, '192.168.43.6', '52.41.99.97', 59678, 443, 40, 128, 'W', 'TCP', 'FA', '2022-01-20', '12:30:54', '[IP]'),
(3, '192.168.43.6', '52.41.99.97', 59678, 443, 40, 128, 'W', 'TCP', 'RA', '2022-01-20', '12:30:54', '[IP]'),
(4, '52.41.99.97', '192.168.43.6', 443, 59681, 40, 227, 'O', 'TCP', 'R', '2022-01-20', '12:30:58', '[IP]'),
(5, '52.41.99.97', '192.168.43.6', 443, 59678, 40, 227, 'O', 'TCP', 'R', '2022-01-20', '12:30:59', '[IP]'),
(6, '140.82.114.25', '192.168.43.6', 443, 59652, 65, 41, 'O', 'TCP', 'PA', '2022-01-20', '12:31:06', '[IP]'),
(7, '192.168.43.6', '140.82.114.25', 59652, 443, 69, 128, 'W', 'TCP', 'PA', '2022-01-20', '12:31:06', '[IP]'),
(8, '140.82.114.25', '192.168.43.6', 443, 59652, 40, 41, 'O', 'TCP', 'A', '2022-01-20', '12:31:08', '[IP]'),
(9, '192.168.43.6', '157.240.198.35', 51510, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:52', '[IP]'),
(10, '192.168.43.6', '157.240.198.35', 51510, 443, 106, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:53', '[IP]'),
(11, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:53', '[IP]'),
(12, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:54', '[IP]'),
(13, '157.240.198.35', '192.168.43.6', 443, 51510, 214, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:54', '[IP]'),
(14, '157.240.198.35', '192.168.43.6', 443, 51510, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:55', '[IP]'),
(15, '157.240.198.35', '192.168.43.6', 443, 51510, 83, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:55', '[IP]'),
(16, '192.168.43.6', '157.240.198.35', 51510, 443, 109, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:55', '[IP]'),
(17, '192.168.43.6', '157.240.198.35', 51510, 443, 1274, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:56', '[IP]'),
(18, '192.168.43.6', '157.240.198.35', 51510, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:56', '[IP]'),
(19, '192.168.43.6', '157.240.198.35', 51510, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:56', '[IP]'),
(20, '192.168.43.6', '157.240.198.35', 51510, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:57', '[IP]'),
(21, '192.168.43.6', '157.240.198.35', 51510, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:57', '[IP]'),
(22, '192.168.43.6', '157.240.198.35', 51510, 443, 253, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:31:58', '[IP]'),
(23, '157.240.198.35', '192.168.43.6', 443, 51510, 67, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:59', '[IP]'),
(24, '157.240.198.35', '192.168.43.6', 443, 51510, 111, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:31:59', '[IP]'),
(25, '157.240.198.35', '192.168.43.6', 443, 51510, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:00', '[IP]'),
(26, '157.240.198.35', '192.168.43.6', 443, 51510, 51, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:00', '[IP]'),
(27, '157.240.198.35', '192.168.43.6', 443, 51510, 269, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:00', '[IP]'),
(28, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:00', '[IP]'),
(29, '157.240.198.35', '192.168.43.6', 443, 51510, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:01', '[IP]'),
(30, '192.168.43.6', '157.240.198.35', 51510, 443, 63, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:01', '[IP]'),
(31, '192.168.43.6', '157.240.198.35', 51510, 443, 61, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:02', '[IP]'),
(32, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:02', '[IP]'),
(33, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:03', '[IP]'),
(34, '157.240.198.35', '192.168.43.6', 443, 51510, 482, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:03', '[IP]'),
(35, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:04', '[IP]'),
(36, '192.168.43.6', '157.240.198.35', 51510, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:04', '[IP]'),
(37, '157.240.198.35', '192.168.43.6', 443, 51510, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:05', '[IP]'),
(38, '157.240.198.35', '192.168.43.6', 443, 51510, 52, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:05', '[IP]'),
(39, '192.168.43.6', '157.240.198.35', 51510, 443, 249, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:07', '[IP]'),
(40, '192.168.43.6', '157.240.239.1', 54431, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:07', '[IP]'),
(41, '192.168.43.6', '157.240.239.1', 54431, 443, 101, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:07', '[IP]'),
(42, '157.240.198.35', '192.168.43.6', 443, 51510, 56, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:08', '[IP]'),
(43, '157.240.239.1', '192.168.43.6', 443, 54431, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:08', '[IP]'),
(44, '192.168.43.6', '157.240.198.35', 51510, 443, 63, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:09', '[IP]'),
(45, '157.240.239.1', '192.168.43.6', 443, 54431, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:09', '[IP]'),
(46, '157.240.239.1', '192.168.43.6', 443, 54431, 214, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:10', '[IP]'),
(47, '157.240.239.1', '192.168.43.6', 443, 54431, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:10', '[IP]'),
(48, '157.240.239.1', '192.168.43.6', 443, 54431, 83, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:10', '[IP]'),
(49, '192.168.43.6', '157.240.239.1', 54431, 443, 109, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:11', '[IP]'),
(50, '192.168.43.6', '157.240.239.1', 54431, 443, 63, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:11', '[IP]'),
(51, '157.240.239.1', '192.168.43.6', 443, 54431, 67, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:12', '[IP]'),
(52, '157.240.239.1', '192.168.43.6', 443, 54431, 111, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:12', '[IP]'),
(53, '157.240.239.1', '192.168.43.6', 443, 54431, 271, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:12', '[IP]'),
(54, '192.168.43.6', '157.240.239.1', 54431, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:12', '[IP]'),
(55, '192.168.43.6', '157.240.198.35', 51510, 443, 61, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:13', '[IP]'),
(56, '157.240.198.35', '192.168.43.6', 443, 51510, 52, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:14', '[IP]'),
(57, '157.240.198.35', '192.168.43.6', 443, 51510, 327, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:14', '[IP]'),
(58, '192.168.43.6', '157.240.198.35', 51510, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:15', '[IP]'),
(59, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:15', '[IP]'),
(60, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:15', '[IP]'),
(61, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:16', '[IP]'),
(62, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:16', '[IP]'),
(63, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:17', '[IP]'),
(64, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:17', '[IP]'),
(65, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:18', '[IP]'),
(66, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:18', '[IP]'),
(67, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:19', '[IP]'),
(68, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:19', '[IP]'),
(69, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:20', '[IP]'),
(70, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:20', '[IP]'),
(71, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:21', '[IP]'),
(72, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:21', '[IP]'),
(73, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:21', '[IP]'),
(74, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:22', '[IP]'),
(75, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:22', '[IP]'),
(76, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:23', '[IP]'),
(77, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:23', '[IP]'),
(78, '157.240.198.35', '192.168.43.6', 443, 51510, 710, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:23', '[IP]'),
(79, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:24', '[IP]'),
(80, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:24', '[IP]'),
(81, '192.168.43.6', '157.240.198.35', 51510, 443, 63, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:25', '[IP]'),
(82, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:25', '[IP]'),
(83, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:25', '[IP]'),
(84, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:26', '[IP]'),
(85, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:26', '[IP]'),
(86, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:27', '[IP]'),
(87, '157.240.198.35', '192.168.43.6', 443, 51510, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:27', '[IP]'),
(88, '157.240.198.35', '192.168.43.6', 443, 51510, 397, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:28', '[IP]'),
(89, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:28', '[IP]'),
(90, '192.168.43.6', '157.240.198.35', 51510, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:29', '[IP]'),
(91, '192.168.43.6', '157.240.239.1', 60017, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:29', '[IP]'),
(92, '192.168.43.6', '157.240.239.1', 60017, 443, 107, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:29', '[IP]'),
(93, '192.168.43.6', '157.240.239.1', 60017, 443, 500, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:30', '[IP]'),
(94, '192.168.43.6', '157.240.239.1', 60017, 443, 151, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:30', '[IP]'),
(95, '192.168.43.6', '157.240.239.1', 60017, 443, 152, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:30', '[IP]'),
(96, '192.168.43.6', '157.240.239.1', 60017, 443, 152, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:31', '[IP]'),
(97, '192.168.43.6', '157.240.239.1', 60017, 443, 152, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:31', '[IP]'),
(98, '192.168.43.6', '157.240.239.1', 60017, 443, 153, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:31', '[IP]'),
(99, '192.168.43.6', '157.240.239.1', 60017, 443, 153, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:32', '[IP]'),
(100, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:32', '[IP]'),
(101, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:32', '[IP]'),
(102, '157.240.239.1', '192.168.43.6', 443, 60017, 214, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:33', '[IP]'),
(103, '157.240.239.1', '192.168.43.6', 443, 60017, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:33', '[IP]'),
(104, '157.240.239.1', '192.168.43.6', 443, 60017, 83, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:34', '[IP]'),
(105, '192.168.43.6', '157.240.239.1', 60017, 443, 109, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:34', '[IP]'),
(106, '157.240.239.1', '192.168.43.6', 443, 60017, 58, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:34', '[IP]'),
(107, '157.240.239.1', '192.168.43.6', 443, 60017, 59, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:35', '[IP]'),
(108, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:35', '[IP]'),
(109, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:35', '[IP]'),
(110, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:35', '[IP]'),
(111, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:36', '[IP]'),
(112, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:36', '[IP]'),
(113, '157.240.239.1', '192.168.43.6', 443, 60017, 806, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:37', '[IP]'),
(114, '157.240.239.1', '192.168.43.6', 443, 60017, 58, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:37', '[IP]'),
(115, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:38', '[IP]'),
(116, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:38', '[IP]'),
(117, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:38', '[IP]'),
(118, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:39', '[IP]'),
(119, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:39', '[IP]'),
(120, '157.240.239.1', '192.168.43.6', 443, 60017, 222, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:40', '[IP]'),
(121, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:40', '[IP]'),
(122, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:40', '[IP]'),
(123, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:40', '[IP]'),
(124, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:41', '[IP]'),
(125, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:41', '[IP]'),
(126, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:42', '[IP]'),
(127, '157.240.239.1', '192.168.43.6', 443, 60017, 54, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:42', '[IP]'),
(128, '157.240.239.1', '192.168.43.6', 443, 60017, 67, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:43', '[IP]'),
(129, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:43', '[IP]'),
(130, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:43', '[IP]'),
(131, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:44', '[IP]'),
(132, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:44', '[IP]'),
(133, '192.168.43.6', '157.240.239.1', 60017, 443, 67, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:45', '[IP]'),
(134, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:45', '[IP]'),
(135, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:46', '[IP]'),
(136, '192.168.43.6', '157.240.239.1', 60017, 443, 67, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:46', '[IP]'),
(137, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:47', '[IP]'),
(138, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:47', '[IP]'),
(139, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:47', '[IP]'),
(140, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:48', '[IP]'),
(141, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:48', '[IP]'),
(142, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:49', '[IP]'),
(143, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:49', '[IP]'),
(144, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:50', '[IP]'),
(145, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:50', '[IP]'),
(146, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:50', '[IP]'),
(147, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:51', '[IP]'),
(148, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:51', '[IP]'),
(149, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:52', '[IP]'),
(150, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:52', '[IP]'),
(151, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:53', '[IP]'),
(152, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:53', '[IP]'),
(153, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:53', '[IP]'),
(154, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:54', '[IP]'),
(155, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:54', '[IP]'),
(156, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:55', '[IP]'),
(157, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:55', '[IP]'),
(158, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:55', '[IP]'),
(159, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:56', '[IP]'),
(160, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:56', '[IP]'),
(161, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:57', '[IP]'),
(162, '192.168.43.6', '157.240.239.1', 60017, 443, 141, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:57', '[IP]'),
(163, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:58', '[IP]'),
(164, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:58', '[IP]'),
(165, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:32:58', '[IP]'),
(166, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:59', '[IP]'),
(167, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:32:59', '[IP]'),
(168, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:00', '[IP]'),
(169, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:00', '[IP]'),
(170, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:00', '[IP]'),
(171, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:01', '[IP]'),
(172, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:01', '[IP]'),
(173, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:02', '[IP]'),
(174, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:02', '[IP]'),
(175, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:03', '[IP]'),
(176, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:03', '[IP]'),
(177, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:04', '[IP]'),
(178, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:04', '[IP]'),
(179, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:05', '[IP]'),
(180, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:05', '[IP]'),
(181, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:06', '[IP]'),
(182, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:06', '[IP]'),
(183, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:07', '[IP]'),
(184, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:07', '[IP]'),
(185, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:07', '[IP]'),
(186, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:08', '[IP]'),
(187, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:08', '[IP]'),
(188, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:09', '[IP]'),
(189, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:09', '[IP]'),
(190, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:10', '[IP]'),
(191, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:11', '[IP]'),
(192, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:11', '[IP]'),
(193, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:11', '[IP]'),
(194, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:12', '[IP]'),
(195, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:12', '[IP]'),
(196, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:12', '[IP]'),
(197, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:13', '[IP]'),
(198, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:13', '[IP]'),
(199, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:14', '[IP]'),
(200, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:15', '[IP]'),
(201, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:15', '[IP]'),
(202, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:16', '[IP]'),
(203, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:16', '[IP]'),
(204, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:16', '[IP]'),
(205, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:17', '[IP]'),
(206, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:17', '[IP]'),
(207, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:18', '[IP]'),
(208, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:18', '[IP]'),
(209, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:19', '[IP]'),
(210, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:19', '[IP]'),
(211, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:20', '[IP]'),
(212, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:20', '[IP]'),
(213, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:21', '[IP]'),
(214, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:21', '[IP]'),
(215, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:21', '[IP]'),
(216, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:22', '[IP]'),
(217, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:22', '[IP]'),
(218, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:22', '[IP]'),
(219, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:23', '[IP]'),
(220, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:23', '[IP]'),
(221, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:24', '[IP]'),
(222, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:24', '[IP]'),
(223, '192.168.43.6', '157.240.239.1', 60017, 443, 67, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:25', '[IP]'),
(224, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:25', '[IP]'),
(225, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:26', '[IP]'),
(226, '157.240.239.1', '192.168.43.6', 443, 60017, 52, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:26', '[IP]'),
(227, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:27', '[IP]'),
(228, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:27', '[IP]'),
(229, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:27', '[IP]'),
(230, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:28', '[IP]'),
(231, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:28', '[IP]'),
(232, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:29', '[IP]'),
(233, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:29', '[IP]'),
(234, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:30', '[IP]'),
(235, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:30', '[IP]'),
(236, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:31', '[IP]'),
(237, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:31', '[IP]'),
(238, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:32', '[IP]'),
(239, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:32', '[IP]'),
(240, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:33', '[IP]'),
(241, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:33', '[IP]'),
(242, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:33', '[IP]'),
(243, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:34', '[IP]'),
(244, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:34', '[IP]'),
(245, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:35', '[IP]'),
(246, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:35', '[IP]'),
(247, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:36', '[IP]'),
(248, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:36', '[IP]'),
(249, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:37', '[IP]'),
(250, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:37', '[IP]'),
(251, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:38', '[IP]'),
(252, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:38', '[IP]'),
(253, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:39', '[IP]'),
(254, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:39', '[IP]'),
(255, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:40', '[IP]'),
(256, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:40', '[IP]'),
(257, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:40', '[IP]'),
(258, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:41', '[IP]'),
(259, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:42', '[IP]'),
(260, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:42', '[IP]'),
(261, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:43', '[IP]'),
(262, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:43', '[IP]'),
(263, '157.240.239.1', '192.168.43.6', 443, 60017, 1066, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:44', '[IP]'),
(264, '157.240.239.1', '192.168.43.6', 443, 60017, 51, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:44', '[IP]'),
(265, '192.168.43.6', '157.240.239.1', 60017, 443, 63, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:45', '[IP]'),
(266, '192.168.43.6', '157.240.239.1', 60017, 443, 139, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:45', '[IP]'),
(267, '192.168.43.6', '157.240.239.1', 60017, 443, 147, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:45', '[IP]'),
(268, '157.240.239.1', '192.168.43.6', 443, 60017, 51, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:46', '[IP]'),
(269, '192.168.43.6', '157.240.239.1', 60017, 443, 139, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:46', '[IP]'),
(270, '192.168.43.6', '157.240.239.1', 60017, 443, 173, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:46', '[IP]'),
(271, '157.240.239.1', '192.168.43.6', 443, 60017, 58, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:47', '[IP]'),
(272, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:47', '[IP]'),
(273, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:47', '[IP]'),
(274, '192.168.43.6', '157.240.239.1', 60017, 443, 178, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:48', '[IP]'),
(275, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:48', '[IP]'),
(276, '192.168.43.6', '157.240.239.1', 60017, 443, 178, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:48', '[IP]'),
(277, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:49', '[IP]'),
(278, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:49', '[IP]'),
(279, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:50', '[IP]'),
(280, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:50', '[IP]'),
(281, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:51', '[IP]'),
(282, '157.240.239.1', '192.168.43.6', 443, 60017, 827, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:52', '[IP]'),
(283, '157.240.239.1', '192.168.43.6', 443, 60017, 57, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:52', '[IP]'),
(284, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:53', '[IP]'),
(285, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:53', '[IP]'),
(286, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:54', '[IP]'),
(287, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:54', '[IP]'),
(288, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:55', '[IP]'),
(289, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:55', '[IP]'),
(290, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:56', '[IP]'),
(291, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:56', '[IP]'),
(292, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:57', '[IP]'),
(293, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:57', '[IP]'),
(294, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:58', '[IP]'),
(295, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:33:59', '[IP]'),
(296, '192.168.43.6', '157.240.239.1', 60017, 443, 62, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:33:59', '[IP]'),
(297, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:00', '[IP]'),
(298, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:00', '[IP]'),
(299, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:01', '[IP]'),
(300, '157.240.239.1', '192.168.43.6', 443, 60017, 1177, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:01', '[IP]'),
(301, '192.168.43.6', '157.240.239.1', 60017, 443, 63, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:34:02', '[IP]'),
(302, '192.168.43.6', '157.240.239.35', 50562, 443, 1278, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:34:02', '[IP]'),
(303, '157.240.239.1', '192.168.43.6', 443, 60017, 58, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:03', '[IP]'),
(304, '157.240.239.1', '192.168.43.6', 443, 60017, 58, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:03', '[IP]'),
(305, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:03', '[IP]'),
(306, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:04', '[IP]'),
(307, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:04', '[IP]'),
(308, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:05', '[IP]'),
(309, '192.168.43.6', '157.240.239.1', 60017, 443, 67, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:34:05', '[IP]'),
(310, '192.168.43.6', '157.240.239.1', 60017, 443, 66, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:34:06', '[IP]'),
(311, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:06', '[IP]'),
(312, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:06', '[IP]'),
(313, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:07', '[IP]'),
(314, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:07', '[IP]'),
(315, '157.240.239.1', '192.168.43.6', 443, 60017, 146, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:08', '[IP]'),
(316, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:08', '[IP]'),
(317, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:09', '[IP]'),
(318, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:09', '[IP]'),
(319, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:09', '[IP]'),
(320, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:10', '[IP]'),
(321, '157.240.239.1', '192.168.43.6', 443, 60017, 1260, 80, 'O', 'UDP', 'NULL', '2022-01-20', '12:34:11', '[IP]'),
(322, '192.168.43.6', '157.240.239.1', 60017, 443, 67, 128, 'W', 'UDP', 'NULL', '2022-01-20', '12:34:11', '[IP]');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `packet`
--
ALTER TABLE `packet`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `packet`
--
ALTER TABLE `packet`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=323;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
