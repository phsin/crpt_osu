﻿
// Функция выполняет формирование изображения штрихкода.
// Параметры: 
//   ПараметрыШтрихкода 
// Возвращаемое значение: 
//   Картинка - Картинка со сформированным штрихкодом или НЕОПРЕДЕЛЕНО.
Функция ПолучитьКартинкуШтрихкода(ПараметрыШтрихкода) Экспорт
	
	ВнешняяКомпонента = ПодключитьВнешнююКомпонентуПечатиШтрихкода();
	
	Если ВнешняяКомпонента = Неопределено Тогда
		ВызватьИсключение НСтр("ru = 'Ошибка подключения внешней компоненты печати штрихкода.'");
	КонецЕсли;
	
	// Зададим размер формируемой картинки.
	ВнешняяКомпонента.Ширина = Окр(ПараметрыШтрихкода.Ширина);
	ВнешняяКомпонента.Высота = Окр(ПараметрыШтрихкода.Высота);
	
	ВнешняяКомпонента.АвтоТип = Ложь;
	
		ВнешняяКомпонента.АвтоТип = Ложь;
		ВнешняяКомпонента.ТипКода = ПараметрыШтрихкода.ТипКода;
	
	Если ПараметрыШтрихкода.Свойство("ПрозрачныйФон") Тогда
		ВнешняяКомпонента.ПрозрачныйФон = ПараметрыШтрихкода.ПрозрачныйФон;
	КонецЕсли;
	
	Если ПараметрыШтрихкода.Свойство("GS1DatabarКоличествоСтрок") Тогда
		ВнешняяКомпонента.GS1DatabarКоличествоСтрок = ПараметрыШтрихкода.GS1DatabarКоличествоСтрок;
	КонецЕсли;
	
	ВнешняяКомпонента.ОтображатьТекст = ПараметрыШтрихкода.ОтображатьТекст;
	
	// Формируем картинку штрихкода.
	ВнешняяКомпонента.ЗначениеКода = ПараметрыШтрихкода.Штрихкод;
	// Угол поворота штрихкода.
	ВнешняяКомпонента.УголПоворота = ?(ПараметрыШтрихкода.Свойство("УголПоворота"), ПараметрыШтрихкода.УголПоворота, 0);
	// Уровень коррекции QR кода (L=0, M=1, Q=2, H=3).
	ВнешняяКомпонента.УровеньКоррекцииQR = ?(ПараметрыШтрихкода.Свойство("УровеньКоррекцииQR"), ПараметрыШтрихкода.УровеньКоррекцииQR, 1);
	
	// Для обеспечения совместимости с предыдущими версиями БПО.
	Если Не ПараметрыШтрихкода.Свойство("Масштабировать")
		Или (ПараметрыШтрихкода.Свойство("Масштабировать") И ПараметрыШтрихкода.Масштабировать) Тогда
		
		Если Не ПараметрыШтрихкода.Свойство("СохранятьПропорции")
				Или (ПараметрыШтрихкода.Свойство("СохранятьПропорции") И Не ПараметрыШтрихкода.СохранятьПропорции) Тогда
			
			// Если установленная нами ширина меньше минимально допустимой для этого штрихкода.
			Если ВнешняяКомпонента.Ширина < ВнешняяКомпонента.МинимальнаяШиринаКода Тогда
				ВнешняяКомпонента.Ширина = ВнешняяКомпонента.МинимальнаяШиринаКода;
			КонецЕсли;
			
			// Если установленная нами высота меньше минимально допустимой для этого штрихкода.
			Если ВнешняяКомпонента.Высота < ВнешняяКомпонента.МинимальнаяВысотаКода Тогда
				ВнешняяКомпонента.Высота = ВнешняяКомпонента.МинимальнаяВысотаКода;
			КонецЕсли;
			
		ИначеЕсли ПараметрыШтрихкода.Свойство("СохранятьПропорции") И ПараметрыШтрихкода.СохранятьПропорции Тогда
			
			Пока ВнешняяКомпонента.Ширина < ВнешняяКомпонента.МинимальнаяШиринаКода 
				Или ВнешняяКомпонента.Высота < ВнешняяКомпонента.МинимальнаяВысотаКода Цикл
				
				// Если установленная нами ширина меньше минимально допустимой для этого штрихкода.
				Если ВнешняяКомпонента.Ширина < ВнешняяКомпонента.МинимальнаяШиринаКода Тогда
					ВнешняяКомпонента.Ширина = ВнешняяКомпонента.МинимальнаяШиринаКода;
					ВнешняяКомпонента.Высота = (ВнешняяКомпонента.МинимальнаяШиринаКода / Окр(ПараметрыШтрихкода.Ширина)) * Окр(ПараметрыШтрихкода.Высота);
				КонецЕсли;
				
				// Если установленная нами высота меньше минимально допустимой для этого штрихкода.
				Если ВнешняяКомпонента.Высота < ВнешняяКомпонента.МинимальнаяВысотаКода Тогда
					ВнешняяКомпонента.Высота = ВнешняяКомпонента.МинимальнаяВысотаКода;
					ВнешняяКомпонента.Ширина = (ВнешняяКомпонента.МинимальнаяВысотаКода / Окр(ПараметрыШтрихкода.Высота)) * Окр(ПараметрыШтрихкода.Ширина);
				КонецЕсли;
				
			КонецЦикла;
			
		КонецЕсли;
	КонецЕсли;
	
	// ВертикальноеВыравниваниеКода: 1 - по верхнему краю, 2 - по центру, 3 - по нижнему краю.
	Если ПараметрыШтрихкода.Свойство("ВертикальноеВыравнивание") И (ПараметрыШтрихкода.ВертикальноеВыравнивание > 0) Тогда
		ВнешняяКомпонента.ВертикальноеВыравниваниеКода = ПараметрыШтрихкода.ВертикальноеВыравнивание;
	КонецЕсли;

	Если ПараметрыШтрихкода.Свойство("РазмерШрифта") И (ПараметрыШтрихкода.РазмерШрифта > 0) 
		И (ПараметрыШтрихкода.ОтображатьТекст) И (ВнешняяКомпонента.РазмерШрифта <> ПараметрыШтрихкода.РазмерШрифта) Тогда
		ВнешняяКомпонента.РазмерШрифта = ПараметрыШтрихкода.РазмерШрифта;
	КонецЕсли;
	
	Если ПараметрыШтрихкода.Свойство("РазмерШрифта") И ПараметрыШтрихкода.РазмерШрифта > 0
		И ПараметрыШтрихкода.Свойство("МонохромныйШрифт") Тогда
		
		Если ПараметрыШтрихкода.МонохромныйШрифт Тогда
			ВнешняяКомпонента.МаксимальныйРазмерШрифтаДляПринтеровНизкогоРазрешения = ПараметрыШтрихкода.РазмерШрифта + 1;
		Иначе
			ВнешняяКомпонента.МаксимальныйРазмерШрифтаДляПринтеровНизкогоРазрешения = -1;
		КонецЕсли;
		
	КонецЕсли;
	
	// Сформируем картинку
	ДвоичныеДанныеКартинки = ВнешняяКомпонента.ПолучитьШтрихкод();
	
	// Если картинка сформировалась.
	Если ДвоичныеДанныеКартинки <> Неопределено Тогда
		// Формируем из двоичных данных.
		Возврат Новый Картинка(ДвоичныеДанныеКартинки);
	КонецЕсли;
	
	Возврат Неопределено;

КонецФункции

// Функция выполняет подключение внешней компоненты и ее первоначальную настройку.
// Возвращаемое значение: НЕОПРЕДЕЛЕНО - компоненту не удалось загрузить.
Функция ПодключитьВнешнююКомпонентуПечатиШтрихкода() Экспорт
	
	#Если НЕ МобильноеПриложениеСервер Тогда  
		УстановитьОтключениеБезопасногоРежима(Истина);
	#КонецЕсли
	ВнешняяКомпонента = ПодключитьКомпонентуИзМакета("Barcode", "ОбщийМакет.КомпонентаПечатиШтрихкодов");
	
	Если ВнешняяКомпонента = Неопределено Тогда 
		Возврат Неопределено;
	КонецЕсли;
	
	// Если нет возможности рисовать.
	Если НЕ ВнешняяКомпонента.ГрафикаУстановлена Тогда
		// То картинку сформировать не сможем.
		Возврат Неопределено;
	Иначе
		// Установим основные параметры компоненты.
		// Если в системе установлен шрифт Tahoma.
		Если ВнешняяКомпонента.НайтиШрифт("Tahoma") Тогда
			// Выбираем его как шрифт для формирования картинки.
			ВнешняяКомпонента.Шрифт = "Tahoma";
		Иначе
			// Шрифт Tahoma в системе отсутствует.
			// Обойдем все доступные компоненте шрифты.
			Для Сч = 0 По ВнешняяКомпонента.КоличествоШрифтов -1 Цикл
				// Получим очередной шрифт, доступный компоненте.
				ТекущийШрифт = ВнешняяКомпонента.ШрифтПоИндексу(Сч);
				// Если шрифт доступен
				Если ТекущийШрифт <> Неопределено Тогда
					// Они и будет шрифтом для формирования штрихкода.
					ВнешняяКомпонента.Шрифт = ТекущийШрифт;
					Прервать;
				КонецЕсли;
			КонецЦикла;
		КонецЕсли;
		// Установим размер шрифта
		ВнешняяКомпонента.РазмерШрифта = 12;
		
		Возврат ВнешняяКомпонента;
	КонецЕсли;
	
КонецФункции

// Подключает компоненту, выполненную по технологии Native API и COM.
// Компонента должна храниться в макете конфигурации в виде ZIP-архива.
//
// Параметры:
//  Идентификатор   - Строка - идентификатор объекта внешней компоненты.
//  ПолноеИмяМакета - Строка - полное имя макета конфигурации, хранящего ZIP-архив.
//
// Возвращаемое значение:
//  AddIn, Неопределено - экземпляр объекта внешней компоненты или Неопределено, если не удалось создать.
//
// Пример:
//
//  ПодключаемыйМодуль = ОбщегоНазначения.ПодключитьКомпонентуИзМакета(
//      "CNameDecl",
//      "ОбщийМакет.КомпонентаСклоненияФИО");
//
//  Если ПодключаемыйМодуль <> Неопределено Тогда 
//      // ПодключаемыйМодуль содержит созданный экземпляр подключенной компоненты.
//  КонецЕсли;
//
//  ПодключаемыйМодуль = Неопределено;
//
Функция ПодключитьКомпонентуИзМакета(Идентификатор, ПолноеИмяМакета) Экспорт

	ПодключаемыйМодуль = Неопределено;
	 		
	Местоположение = ПолноеИмяМакета;
	СимволическоеИмя = Идентификатор + "SymbolicName";
	
	Если ПодключитьВнешнююКомпоненту(Местоположение, СимволическоеИмя) Тогда
		Попытка
			ПодключаемыйМодуль = Новый("AddIn." + СимволическоеИмя + "." + Идентификатор);
			Если ПодключаемыйМодуль = Неопределено Тогда 
				ВызватьИсключение НСтр("ru = 'Оператор Новый вернул Неопределено'");
			КонецЕсли;
		Исключение
			ПодключаемыйМодуль = Неопределено;
			ТекстОшибки = КраткоеПредставлениеОшибки(ИнформацияОбОшибке());
			кб99_Общие.СообщитьИнфо(ТекстОшибки, , , , ИСТИНА);
		КонецПопытки;
	Иначе
		ТекстОшибки = НСтр("ru = 'Не удалось подключить внешнюю компоненту для генерации QR-кода'");
		кб99_Общие.СообщитьИнфо(ТекстОшибки, , , , ИСТИНА);
	КонецЕсли;
	
	Возврат ПодключаемыйМодуль;
	
КонецФункции

// Возвращает сгенерированный штрихкод SSCC по переданным параметрам
//
// Параметры:
// 	ПараметрыШтрихкода  - Структура - Структура входящих параметров штрихкода
// 	 * ЦифраРасширения    - Число - Цифра расширения SSCC
// 	 * ПрефиксКомпанииGS1 - Число - префикс компании GS1
// 	 * СерийныйНомерSSCC  - Число - серийный номер SSCC
// 	УстанавливатьСкобки - Булево    - Если истина, то идентификатор SSCC 00 будет помещен в скобки.
//
// Возвращаемое значение:
// 	Строка - Сгенерированный штрихкод
//
Функция ШтрихкодSSCC(ПараметрыШтрихкода, УстанавливатьСкобки = Истина) Экспорт
	
	ЦифраРасширения    = ПараметрыШтрихкода.ЦифраРасширения;
	ПрефиксКомпанииGS1 = ПараметрыШтрихкода.ПрефиксКомпанииGS1;
	СерийныйНомерSSCC  = ПараметрыШтрихкода.СерийныйНомерSSCC;
	
	Если ЗначениеЗаполнено(ПрефиксКомпанииGS1)
	   И ЗначениеЗаполнено(СерийныйНомерSSCC) Тогда
		
		Штрихкод = Формат(ЦифраРасширения, "ЧН=0; ЧГ=0")
			+ ПриведенноеКДлинеЗначение(ПрефиксКомпанииGS1, 9)
			+ ПриведенноеКДлинеЗначение(СерийныйНомерSSCC, 7);
		
		КонтрольноеЧисло = КонтрольноеЧислоSSCC(Штрихкод);
		
		Если УстанавливатьСкобки Тогда
			Штрихкод = "(00)" + Штрихкод + КонтрольноеЧисло;
		Иначе
			Штрихкод = "00" + Штрихкод + КонтрольноеЧисло;
		КонецЕсли;
	Иначе
		
		Штрихкод = "";
		
	КонецЕсли;
	
	Возврат Штрихкод;
	
КонецФункции

// Возвращает рассчитанное контрольное число.
//
// Параметры:
// 	Штрихкод - Строка - часть штрихкода SSCC, состоящая из цифр, без идентификатора применения SSCC
// 	                    (00 или (00)) и без контрольной цифры
//
// Возвращаемое значение:
// 	Число - Цифра контрольного числа SSCC
//
Функция КонтрольноеЧислоSSCC(Штрихкод)
	КонтрольноеЧисло = 0;
	
	Цифры = Новый Массив;
	Позиций  = СтрДлина(Штрихкод);
	Для НомерПозиции = 1 По Позиций Цикл
		Цифры.Добавить(СтрокаВЧисло(Сред(Штрихкод, НомерПозиции, 1)));
	КонецЦикла;
	
	СуммаЧетных = 0;
	СуммаНечетных = 0;
	Для НомерПозиции = 0 По Позиций-1 Цикл
		Если НомерПозиции%2=0 Тогда
			СуммаЧетных=СуммаЧетных+Цифры[НомерПозиции];
		Иначе
			СуммаНечетных=СуммаНечетных+Цифры[НомерПозиции];
		КонецЕсли;
	КонецЦикла;
	
	СверяемоеЧисло = СуммаЧетных * 3 + СуммаНечетных;
	КонтрольноеЧисло = 10 - СверяемоеЧисло%10;
	Если КонтрольноеЧисло = 10 Тогда
		КонтрольноеЧисло = 0;
	КонецЕсли;
	
	Возврат КонтрольноеЧисло;
КонецФункции

Функция ПриведенноеКДлинеЗначение(Знач ИсходнаяСтрока, Длина) Экспорт
	Если ТипЗнч(ИсходнаяСтрока) = Тип("Число") Тогда
		Строка = Формат(ИсходнаяСтрока, "ЧН=0; ЧГ=0");
	Иначе
		Строка = СокрЛП(ИсходнаяСтрока);
	КонецЕсли;
	ТекущаяДлина = СтрДлина(Строка);
	Пока ТекущаяДлина < Длина Цикл
		Строка = "0" + Строка;
		ТекущаяДлина = ТекущаяДлина + 1;
	КонецЦикла;
	
	Возврат Строка;
КонецФункции

// Преобразует исходную строку в число без вызова исключений.
//
// Параметры:
//   Значение - Строка - строка, которую необходимо привести к числу.
//                       Например, "10", "+10", "010", вернет 10;
//                                 "(10)", "-10",вернет -10;
//                                 "10,2", "10.2",вернет 10.2;
//                                 "000", " ", "",вернет 0;
//                                 "10текст", вернет Неопределено.
//
// Возвращаемое значение:
//   Число, Неопределено - полученное число, либо Неопределено, если строка не является числом.
//
Функция СтрокаВЧисло(Знач Значение) Экспорт
	
	Значение  = СтрЗаменить(Значение, " ", "");
	Если СтрНачинаетсяС(Значение, "(") Тогда
		Значение = СтрЗаменить(Значение, "(", "-");
		Значение = СтрЗаменить(Значение, ")", "");
	КонецЕсли;
	
	СтрокаБезНулей = СтрЗаменить(Значение, "0", "");
	Если ПустаяСтрока(СтрокаБезНулей) Или СтрокаБезНулей = "-" Тогда
		Возврат 0;
	КонецЕсли;
	
	ТипЧисло  = Новый ОписаниеТипов("Число");
	Результат = ТипЧисло.ПривестиЗначение(Значение);
	
	Возврат ?(Результат <> 0 И Не ПустаяСтрока(СтрокаБезНулей), Результат, Неопределено);
	
КонецФункции

// Получаем значение штрихкода  SSCC без идентификатора
Функция ДанныеШтрихкодаSSCC(Знач Штрихкод) Экспорт
	
	КлючИдентификатораSSCC = "00";
	КлючИдентификатораSSCCПолный = "(00)";
	
	НомерПозицииСоСкобками = СтрНайти(Штрихкод, КлючИдентификатораSSCCПолный);
	НомерПозиции = СтрНайти(Штрихкод, КлючИдентификатораSSCC);
	
	Если НомерПозицииСоСкобками = 1 Тогда
		НепрочитаннаяЧастьШК = Сред(Штрихкод, СтрДлина(КлючИдентификатораSSCCПолный) + 1);
	ИначеЕсли НомерПозиции = 1 Тогда
		НепрочитаннаяЧастьШК = Сред(Штрихкод, СтрДлина(КлючИдентификатораSSCC) + 1);
	Иначе
		НепрочитаннаяЧастьШК = Штрихкод;
	КонецЕсли;
	
	Возврат НепрочитаннаяЧастьШК;
	
КонецФункции
