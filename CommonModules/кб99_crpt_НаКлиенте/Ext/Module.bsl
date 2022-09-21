//Функция Reg( sThumbprint, bDetached, debugMessages=Ложь ) Экспорт
Функция Reg( ПараметрыПользователя ) Экспорт
	
	//ПараметрыОрганизации = кб99_Общие.НайтиПараметры( ПараметрыСеанса.ТекущийПользователь);

	htmlAttributes  = кб99_crpt.ПолучитьКлючИСМП( ПараметрыПользователя );
	//АдресСервера = кб99_crpt.АдресСервера(ПараметрыПользователя["ТестовыйКонтур"], Ложь, Истина);
	//	
	//jsonResult = кб99_crpt.SendGet(АдресСервера, "/api/v3/auth/cert/key");
	//
	//Если ПараметрыПользователя.ВыводитьСообщенияДляОтладки Тогда 
	//	кб99_crpt.СохранитьЗапросВРегистрСведений( АдресСервера+"/api/v3/auth/cert/key", jsonResult );
	//	кб99_Общие.СообщитьИнфо(jsonResult);
	//КонецЕсли;

	//htmlAttributes = jsonПрочитать(jsonResult);
	sKey = htmlAttributes["data"];
	//
	ДвоичныеДанныеСтроки = ПолучитьДвоичныеДанныеИзСтроки( sKey );
	str = Base64Строка(ДвоичныеДанныеСтроки);	

	bDetached = Ложь; //Истина;
	sThumbprint = ПараметрыПользователя.Отпечаток;
	sKeySigned = SignText(str, sThumbprint, bDetached);
	sKeySigned = СтрЗаменить(sKeySigned, "\r\n", "");
	
	
	
	Данные = Новый Структура;
	Данные.Вставить("uuid", htmlAttributes["uuid"]);
	Данные.Вставить("data", sKeySigned);
	Запись = Новый ЗаписьJSON;
	ПараметрыЗаписиJSON = Новый ПараметрыЗаписиJSON(ПереносСтрокJSON.Авто, Символы.Таб);	
		
	Запись = Новый ЗаписьJSON;
	Запись.УстановитьСтроку();	
	ЗаписатьJSON(Запись, Данные);	
	СтрокаJSON = Запись.Закрыть();	
	
	Токен = кб99_crpt.ОтправитьПодписанныйКлючИСМП( ПараметрыПользователя , СтрокаJSON );
	//кб99_Общие.СообщитьИнфо( СтрокаJSON );
	ОбщегоНазначенияКлиент.СообщитьПользователю( СтрокаJSON );
	
	//Заголовки = Новый Соответствие;
	//Заголовки.Вставить("Connection", "keep-alive");
	//Заголовки.Вставить("Content-Type", "application/json;charset=UTF-8");
	//
	////Адрес = "/api/v3/auth/simpleSignIn/"; //не проходит
	//Адрес = "/api/v3/auth/cert/";
	//ResultPost = SendPost(АдресСервера, Адрес, СтрокаJSON, Заголовки);

	//jsonResultPost = jsonПрочитать(ResultPost);
	//Если jsonResultPost.Получить("error_message") <> Неопределено Тогда
	//	кб99_Общие.СообщитьИнфо(jsonResultPost.Получить("error_message"));
	//	кб99_Общие.СообщитьИнфо(jsonResultPost.Получить("description"));
	//	СохранитьЗапросВРегистрСведений( АдресСервера + Адрес + СтрокаJSON, ResultPost );
	//	Возврат Неопределено;
	//КонецЕсли;

	//token = jsonResultPost["token"];

	//СохранитьЗапросВРегистрСведений( АдресСервера + Адрес + СтрокаJSON, ResultPost );
	//кб99_Общие.СообщитьИнфо( token );

    Возврат Токен;
	
КонецФункции

#Область КриптоПро

Функция SignText( sInput, sThumbprint, bDetached, ЗапросBase64 = Истина) Экспорт
		
	oSigningTimeAttr =  Новый COMОбъект("CAdESCOM.CPAttribute");
    oSigningTimeAttr.Name = 0; // CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0; //CAdESCOM.CADESCOM_ATTRIBUTE.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME	
    oSigningTimeAttr.Value = ТекущаяДата();
	
    oSigner = Новый COMОбъект("CAdESCOM.CPSigner");    // Объект, задающий параметры создания и содержащий информацию об усовершенствованной подписи.
	Сертификат = GetCertificateByThumbprint(sThumbprint);
	Если  Сертификат <> Неопределено Тогда 
		oSigner.Certificate = Сертификат;
	Иначе
		Возврат "Сертификат не найден";
	КонецЕсли;
    oSigner.AuthenticatedAttributes2.Add(oSigningTimeAttr);
	oSigner.Options = 2;
	
    oSignedData =  Новый COMОбъект("CAdESCOM.CadesSignedData"); // Объект CadesSignedData предоставляет свойства и методы для работы с усовершенствованной подписью.
    oSignedData.ContentEncoding = ?(ЗапросBase64,1,0); // Входные данные пришли в Base64 // CADESCOM_BASE64_TO_BINARY = 1; //CAdESCOM.CADESCOM_CONTENT_ENCODING_TYPE.CADESCOM_BASE64_TO_BINARY
    oSignedData.Content = sInput;
	
	CADESCOM_CADES_BES = 1; // Тип усовершенствованной подписи //CAdESCOM.CADESCOM_CADES_TYPE.CADESCOM_CADES_BES https://cpdn.cryptopro.ru/content/cades/namespace_c_ad_e_s_c_o_m_fe49883d8ff77f7edbeeaf0be3d44c0b_1fe49883d8ff77f7edbeeaf0be3d44c0b.html
	CAPICOM_ENCODE_BASE64 = 0; // CAdESCOM.CAPICOM_ENCODING_TYPE.CAPICOM_ENCODE_BASE64
    sSignedMessage = oSignedData.SignCades(oSigner, CADESCOM_CADES_BES, bDetached,  CAPICOM_ENCODE_BASE64 );
    // Метод добавляет к сообщению усовершенствованную подпись.
    return sSignedMessage; // Подпись в формате Base64
	
КонецФункции


Функция GetCertificateByThumbprint( sThumbprint)  Экспорт
    Result = Неопределено;  // Найденный сертификат (Com-объект)
    CAPICOM_CURRENT_USER_STORE = 2; //2 - Искать сертификат в ветке "Личное" хранилища.
    CAPICOM_MY_STORE = "My";
    // Указываем, что ветку "Личное" берем из хранилища текущего пользователя
    CAPICOM_STORE_OPEN_READ_ONLY = 1; // Открыть хранилище только на чтение

    oStore = Новый COMОбъект("CAdESCOM.Store");// .Store(); // Объект описывает хранилище сертификатов
    oStore.Open( CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_READ_ONLY ); // Открыть хранилище сертификатов
    // 1 вариант: поиск сертификата по отпечатку
    //var CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
    //var Certificates = oStore.Certificates.Find(CAPICOM_CERTIFICATE_FIND_SHA1_HASH, sThumbprint);
    //var Result = Certificates.Item(1);
    //2 вариант: обходом по коллекции и сравнение с отпечатком            
    last = "";
	Certs = oStore.Certificates;
	для каждого Сертификат из Certs Цикл
		Если (Сертификат.Thumbprint = sThumbprint) тогда 
			Result = Сертификат;
		КонецЕсли;
		last = Сертификат.Thumbprint;
	КонецЦикла;
	
	if (Result = Неопределено) Тогда 
		кб99_Общие.СообщитьИнфо("Не найден отпечаток сертификата = " + sThumbprint + "\nпоследний отпечаток = " + last); 
	КонецЕсли;
    oStore.Close(); // Закрыть хранилище сертификатов и освободить объект 61
    return Result;
КонецФункции

#КонецОбласти       

Процедура ПроверитьСрокДействияТокена( ПараметрыПользователя ) Экспорт
	
	Если ПараметрыПользователя.СрокДействияТокена < ТекущаяДата() Или Не ЗначениеЗаполнено(ПараметрыПользователя.clientToken) Тогда
		
		Токен = Reg( ПараметрыПользователя );   

		Если Не ЗначениеЗаполнено( Токен ) Тогда
			ВызватьИсключение "Возникла ошибка при получении токена";	
		КонецЕсли;
		
		кб99_crpt.ЗаписатьНовыйТокенНаСервере( ПараметрыПользователя, Токен );
	КонецЕсли;

КонецПроцедуры
