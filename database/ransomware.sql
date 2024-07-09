-- phpMyAdmin SQL Dump
-- version 2.11.6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 28, 2023 at 06:48 AM
-- Server version: 5.0.51
-- PHP Version: 5.2.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `ransomware`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

CREATE TABLE `admin` (
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL,
  `setpath` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`username`, `password`, `setpath`) VALUES
('admin', 'admin', 'D:\\soft');

-- --------------------------------------------------------

--
-- Table structure for table `attack_file`
--

CREATE TABLE `attack_file` (
  `id` int(11) NOT NULL,
  `filepath` varchar(200) NOT NULL,
  `filename` varchar(100) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `attack_file`
--


-- --------------------------------------------------------

--
-- Table structure for table `hash_file`
--

CREATE TABLE `hash_file` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `filepath` varchar(200) NOT NULL,
  `filename` varchar(100) NOT NULL,
  `hash_file` varchar(100) NOT NULL,
  `recover_status` int(11) NOT NULL,
  `dtype` varchar(20) NOT NULL,
  `dpath` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `hash_file`
--


--
-- Table structure for table `malware_detected`
--

CREATE TABLE `malware_detected` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `url_link` varchar(200) NOT NULL,
  `status` int(11) NOT NULL,
  `date_time` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `malware_detected`
--

--
-- Table structure for table `register`
--

CREATE TABLE `register` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `city` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL,
  `create_date` varchar(20) NOT NULL,
  `status` int(11) NOT NULL,
  `setpath` varchar(100) NOT NULL,
  `ip_address` varchar(30) NOT NULL,
  `mac_address` varchar(30) NOT NULL,
  `secret_code` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `register`
--
-- --------------------------------------------------------

--
-- Table structure for table `selected_file`
--

CREATE TABLE `selected_file` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `file_path` varchar(100) NOT NULL,
  `filetype` varchar(20) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `selected_file`
--

